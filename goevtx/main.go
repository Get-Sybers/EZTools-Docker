// goevtx — Linux-native Windows Event Log (.evtx) parser for the DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's EvtxECmd: it parses .evtx with
// Velociraptor's go-evtx and emits one JSON record per event in the EvtxECmd
// output shape the DX_DFIR evtx lane + the byakugan winevt/evtx maps consume —
// EventId, Provider, Channel, Computer, EventRecordId, TimeCreated, Level,
// UserId, and Payload (the event's EventData rendered as the classic
// {"EventData":{"Data":[{"@Name","#text"}...]}} form, or {"UserData":...}) plus
// SourceFile and a null MapDescription. It runs on Linux with no .NET, no shell
// and no libc (see Dockerfile: FROM scratch, uid 2000).
//
// What it does NOT do (never faked): EvtxECmd's Maps layer — the per-provider
// YAML that derives PayloadData1-6 / MapDescription / ExecutableInfo. byakugan
// reads the RAW EventData out of Payload, not those Maps-derived columns, so the
// substitute is faithful to what the pipeline actually consumes. MapDescription
// is emitted as null.
//
// Output: JSONL (--json/--jsonf) — one event per line, EvtxECmd's *.json shape.
// A best-effort XML sidecar (--xml/--xmlf) reconstructs <Event> per record for
// manual review (not ingested); it is not the original binary XML byte-for-byte.
//
// Exit codes: 0 = every log parsed; 1 = usage or fatal error; 2 = at least one
// file failed to parse (failures listed on stderr, the rest still emitted).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"
)

// record is the EvtxECmd *.json per-event shape the pipeline consumes. Field
// order follows EvtxECmd; byakugan reads by key so order is cosmetic.
type record struct {
	// Every key is always emitted (no omitempty) so the per-event JSON schema is
	// stable across records — a consumer can rely on the field set.
	EventId        int64       `json:"EventId"`
	Level          int64       `json:"Level"`
	Provider       string      `json:"Provider"`
	Channel        string      `json:"Channel"`
	Computer       string      `json:"Computer"`
	EventRecordId  int64       `json:"EventRecordId"`
	TimeCreated    string      `json:"TimeCreated"`
	UserId         string      `json:"UserId"`
	MapDescription interface{} `json:"MapDescription"` // always null — no Maps layer
	SourceFile     string      `json:"SourceFile"`
	Payload        string      `json:"Payload"` // JSON string, EventData/UserData
}

// asText renders an EventData value the way EvtxECmd stamps #text: a plain
// string, never a Go type artefact.
func asText(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		// whole floats print as integers (event ids, pids arrive as numbers)
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}

// buildPayload renders the event's data block as the EvtxECmd Payload JSON
// string: EventData -> {"EventData":{"Data":[{"@Name","#text"}...]}} (the
// classic form byakugan's payload() indexes), UserData -> {"UserData":...}
// passed through (byakugan's userdata() walks its single nested child), else "".
func buildPayload(event *ordereddict.Dict) (string, error) {
	if ed, ok := ordereddict.GetMap(event, "EventData"); ok && ed != nil {
		data := make([]map[string]string, 0, len(ed.Keys()))
		for _, k := range ed.Keys() {
			v, _ := ed.Get(k)
			data = append(data, map[string]string{"@Name": k, "#text": asText(v)})
		}
		b, err := json.Marshal(map[string]interface{}{"EventData": map[string]interface{}{"Data": data}})
		return string(b), err
	}
	if ud, ok := ordereddict.GetMap(event, "UserData"); ok && ud != nil {
		b, err := json.Marshal(map[string]interface{}{"UserData": ud})
		return string(b), err
	}
	return "", nil
}

// systemTime converts go-evtx's TimeCreated.SystemTime (epoch seconds as a
// float) to RFC3339 UTC; "" when absent. byakugan's parse_ts reads this.
func systemTime(system *ordereddict.Dict) string {
	tc, ok := ordereddict.GetMap(system, "TimeCreated")
	if !ok || tc == nil {
		return ""
	}
	v, ok := tc.Get("SystemTime")
	if !ok {
		return ""
	}
	secs, ok := v.(float64)
	if !ok {
		return ""
	}
	sec := int64(secs)
	// round the fractional part and carry, so float error can't yield a nsec
	// outside [0,1e9) (which time.Unix would silently mis-normalise)
	nsec := int64(math.Round((secs - float64(sec)) * 1e9))
	if nsec >= 1_000_000_000 {
		sec++
		nsec -= 1_000_000_000
	} else if nsec < 0 {
		sec--
		nsec += 1_000_000_000
	}
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
}

func eventID(system *ordereddict.Dict) int64 {
	if eid, ok := ordereddict.GetMap(system, "EventID"); ok && eid != nil {
		if v, ok := eid.GetInt64("Value"); ok {
			return v
		}
	}
	if v, ok := system.GetInt64("EventID"); ok { // some renderings inline it
		return v
	}
	return 0
}

func toRecord(event *ordereddict.Dict, sourceFile string) (*record, error) {
	system, ok := ordereddict.GetMap(event, "System")
	if !ok || system == nil {
		return nil, fmt.Errorf("event has no System block")
	}
	provider := ""
	if p, ok := ordereddict.GetMap(system, "Provider"); ok && p != nil {
		provider, _ = p.GetString("Name")
	}
	userID := ""
	if sec, ok := ordereddict.GetMap(system, "Security"); ok && sec != nil {
		userID, _ = sec.GetString("UserID")
	}
	channel, _ := system.GetString("Channel")
	computer, _ := system.GetString("Computer")
	recID, _ := system.GetInt64("EventRecordID")
	level, _ := system.GetInt64("Level")
	payload, err := buildPayload(event)
	if err != nil {
		return nil, fmt.Errorf("render payload: %w", err)
	}
	return &record{
		EventId:       eventID(system),
		Level:         level,
		Provider:      provider,
		Channel:       channel,
		Computer:      computer,
		EventRecordId: recID,
		TimeCreated:   systemTime(system),
		UserId:        userID,
		SourceFile:    sourceFile,
		Payload:       payload,
	}, nil
}

// parseFile streams every event in `path` (a .evtx) to `emitJSON` (and `emitXML`
// when non-nil). Returns (emitted, skipped, err): `skipped` counts torn chunks
// and unrenderable records that were dropped, so a lossy parse is reported
// rather than passing silently as a clean run.
func parseFile(path string, emitJSON func(*record) error, emitXML func(*record) error) (int, int, error) {
	fd, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer fd.Close()
	chunks, err := evtx.GetChunks(fd)
	if err != nil {
		return 0, 0, err
	}
	src := filepath.Base(path)
	n, skipped := 0, 0
	for _, chunk := range chunks {
		records, err := chunk.Parse(0)
		if err != nil {
			skipped++ // a torn chunk is skipped; the rest of the log still parses
			continue
		}
		for _, r := range records {
			em, ok := r.Event.(*ordereddict.Dict)
			if !ok {
				skipped++
				continue
			}
			event, ok := ordereddict.GetMap(em, "Event")
			if !ok || event == nil {
				skipped++
				continue
			}
			rec, err := toRecord(event, src)
			if err != nil {
				skipped++
				continue
			}
			if err := emitJSON(rec); err != nil {
				return n, skipped, err
			}
			if emitXML != nil {
				if err := emitXML(rec); err != nil {
					return n, skipped, err
				}
			}
			n++
		}
	}
	return n, skipped, nil
}

const evtxMagic = "ElfFile\x00"

func looksLikeEvtx(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [8]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == evtxMagic
}

// collectInputs: a single -f file, or every .evtx under -d (by extension or the
// ElfFile signature, so a plaso-renamed name is still found).
func collectInputs(file, dir string) ([]string, error) {
	if file != "" {
		return []string{file}, nil
	}
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return err
			}
			fmt.Fprintf(os.Stderr, "goevtx: skipping unreadable %s: %v\n", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() && (strings.EqualFold(filepath.Ext(p), ".evtx") || looksLikeEvtx(p)) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func openOut(dir, name, defName string) (io.WriteCloser, error) {
	if dir == "" {
		return os.Stdout, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if name == "" {
		name = defName
	}
	return os.Create(filepath.Join(dir, name))
}

// xmlEscape is the minimal escaping for the reconstructed sidecar.
var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

func main() {
	var (
		file    = flag.String("f", "", "single .evtx file to parse")
		dir     = flag.String("d", "", "directory to scan recursively for .evtx")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: EvtxECmd_Output.json)")
		xmlDir  = flag.String("xml", "", "directory to write the best-effort XML sidecar to")
		xmlF    = flag.String("xmlf", "", "XML sidecar file name")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "goevtx: exactly one of -f <file> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}

	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "goevtx: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "goevtx: no .evtx files found")
		os.Exit(1)
	}

	jw, err := openOut(*jsonDir, *jsonF, "EvtxECmd_Output.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "goevtx: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if jw != os.Stdout {
			jw.Close()
		}
	}()
	enc := json.NewEncoder(jw)

	// Optional XML sidecar (best-effort; not ingested).
	var xw io.WriteCloser
	var xbuf *bufio.Writer
	if *xmlDir != "" {
		xw, err = openOut(*xmlDir, *xmlF, "EvtxECmd_Output.xml")
		if err != nil {
			fmt.Fprintf(os.Stderr, "goevtx: %v\n", err)
			os.Exit(1)
		}
		defer xw.Close()
		xbuf = bufio.NewWriter(xw)
		fmt.Fprintln(xbuf, "<Events>")
		defer func() { fmt.Fprintln(xbuf, "</Events>"); xbuf.Flush() }()
	}

	emitJSON := func(r *record) error { return enc.Encode(r) }
	var emitXML func(*record) error
	if xbuf != nil {
		emitXML = func(r *record) error {
			// a compact, escaped reconstruction — System basics + the Payload blob
			fmt.Fprintf(xbuf, "  <Event><System>"+
				"<Provider Name=\"%s\"/><EventID>%d</EventID><Level>%d</Level>"+
				"<TimeCreated SystemTime=\"%s\"/><EventRecordID>%d</EventRecordID>"+
				"<Channel>%s</Channel><Computer>%s</Computer></System>"+
				"<PayloadJson>%s</PayloadJson></Event>\n",
				xmlEscaper.Replace(r.Provider), r.EventId, r.Level, r.TimeCreated,
				r.EventRecordId, xmlEscaper.Replace(r.Channel),
				xmlEscaper.Replace(r.Computer), xmlEscaper.Replace(r.Payload))
			return nil
		}
	}

	failed, parsed, events, skippedTotal := 0, 0, 0, 0
	for _, p := range inputs {
		n, skipped, err := parseFile(p, emitJSON, emitXML)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "goevtx: FAILED %s: %v\n", p, err)
			continue
		}
		parsed++
		events += n
		skippedTotal += skipped
		if !*quiet {
			note := ""
			if skipped > 0 {
				note = fmt.Sprintf(", %d dropped (torn chunk/unrenderable)", skipped)
			}
			fmt.Fprintf(os.Stderr, "goevtx: parsed %s (%d events%s)\n", p, n, note)
		}
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "goevtx: %d events across %d log(s)", events, parsed)
		if skippedTotal > 0 {
			fmt.Fprintf(os.Stderr, "; %d record(s) dropped", skippedTotal)
		}
		fmt.Fprintln(os.Stderr)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "goevtx: %d of %d files failed\n", failed, len(inputs))
		os.Exit(2)
	}
}
