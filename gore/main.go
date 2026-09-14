// gore — Linux-native Windows Registry batch extractor for the DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's RECmd (batch mode): it reads a
// batch definition (.reb — the same YAML RECmd uses) and, for every registry
// hive it is pointed at, extracts the keys/values the batch names, on
// Velociraptor's regparser. One record per value in the shape byakugan's
// recmd_batch map consumes: HivePath, HiveType, Category, Description, Comment,
// KeyPath, ValueName, ValueType, ValueData, LastWriteTimestamp, Recursive,
// Deleted. Runs on Linux with no .NET, no shell, no libc (Dockerfile: FROM
// scratch, uid 2000).
//
// Dirty-hive .LOG1/.LOG2 transaction logs ARE replayed (regparser.RecoverHive)
// unless --nl is given, matching RECmd's dirty-hive handling; the recovered copy
// is written under --work-dir (a writable tmpfs, since the rootfs is read-only).
//
// SCOPE vs RECmd (never faked): gore runs the .reb batch's KEY/VALUE extraction
// (KeyPath, ValueName, Recursive) — it does NOT run RECmd's PLUGINS (the .NET
// per-artefact decoders, e.g. UserAssist ROT13, AppCompatCache), and it does not
// recover *deleted* cells (regparser reads live cells). Records are live values
// (Deleted=false). The bundled batch (batch/default.reb) is a curated
// forensic-key set, NOT Eric Zimmerman's Kroll_Batch.reb (which is not
// redistributed here); supply your own with --bn.
//
// Exit codes: 0 = ok; 1 = usage/fatal; 2 = at least one hive failed to parse.
package main

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"www.velocidex.com/golang/regparser"
)

// batch is a parsed .reb definition. RECmd's .reb is YAML: a Description/Author
// header and a Keys list; gore reads the fields that drive extraction.
type batch struct {
	Description string     `yaml:"Description"`
	Author      string     `yaml:"Author"`
	Keys        []batchKey `yaml:"Keys"`
}

type batchKey struct {
	Description string `yaml:"Description"`
	HiveType    string `yaml:"HiveType"`
	Category    string `yaml:"Category"`
	KeyPath     string `yaml:"KeyPath"`
	ValueName   string `yaml:"ValueName"`
	Recursive   bool   `yaml:"Recursive"`
	Comment     string `yaml:"Comment"`
}

// record is one extracted value — the recmd_batch shape byakugan reads.
type record struct {
	HivePath           string `json:"HivePath"`
	HiveType           string `json:"HiveType"`
	Category           string `json:"Category"`
	Description        string `json:"Description"`
	Comment            string `json:"Comment"`
	KeyPath            string `json:"KeyPath"`
	ValueName          string `json:"ValueName"`
	ValueType          string `json:"ValueType"`
	ValueData          string `json:"ValueData"`
	LastWriteTimestamp string `json:"LastWriteTimestamp"`
	Recursive          bool   `json:"Recursive"`
	Deleted            bool   `json:"Deleted"`
}

var csvHeader = []string{"HivePath", "HiveType", "Category", "Description", "Comment",
	"KeyPath", "ValueName", "ValueType", "ValueData", "LastWriteTimestamp", "Recursive", "Deleted"}

func (r *record) csvRow() []string {
	return []string{r.HivePath, r.HiveType, r.Category, r.Description, r.Comment,
		r.KeyPath, r.ValueName, r.ValueType, r.ValueData, r.LastWriteTimestamp,
		strconv.FormatBool(r.Recursive), strconv.FormatBool(r.Deleted)}
}

// hiveTypeOf maps a hive FILE name to RECmd's HiveType token (RECmd detects it
// from the hive's embedded root; the file name is an exact, reliable proxy for
// the standard hives the batch targets). "" = unknown (skipped for typed keys).
func hiveTypeOf(path string) string {
	switch strings.ToUpper(filepath.Base(path)) {
	case "NTUSER.DAT":
		return "NtUser"
	case "USRCLASS.DAT":
		return "UsrClass"
	case "SYSTEM":
		return "System"
	case "SOFTWARE":
		return "Software"
	case "SAM":
		return "Sam"
	case "SECURITY":
		return "Security"
	case "AMCACHE.HVE":
		return "Amcache"
	}
	return ""
}

// valueDataString renders a value the way the recmd_batch map expects to read
// it: strings/multi-sz/ints as text, binary as hex (never a Go artefact).
func valueDataString(vd *regparser.ValueData) string {
	if vd == nil {
		return ""
	}
	switch {
	case vd.String != "":
		return vd.String
	case len(vd.MultiSz) > 0:
		return strings.Join(vd.MultiSz, " ")
	case vd.Uint64 != 0:
		return strconv.FormatUint(vd.Uint64, 10)
	case len(vd.Data) > 0:
		return hex.EncodeToString(vd.Data)
	}
	return ""
}

func lastWrite(node *regparser.CM_KEY_NODE) string {
	if node == nil {
		return ""
	}
	ft := node.LastWriteTime()
	if ft == nil || ft.Time.IsZero() {
		return ""
	}
	// space-separated: byakugan's recmd_batch normalises " " -> "T" to ISO.
	return ft.Time.UTC().Format("2006-01-02 15:04:05.0000000")
}

// emitKey emits one record per value of `node` (the key found at bk.KeyPath, or
// a subkey when recursing). keyPath is the full path of `node`.
func emitKey(reg *regparser.Registry, node *regparser.CM_KEY_NODE, keyPath string,
	bk batchKey, hivePath, hiveType string, e *emitter) (int, error) {
	if node == nil {
		return 0, nil
	}
	lw := lastWrite(node)
	n := 0
	values := node.Values()
	for _, v := range values {
		name := v.ValueName()
		if bk.ValueName != "" && !strings.EqualFold(name, bk.ValueName) {
			continue // a named-value key emits only that value
		}
		rec := &record{
			HivePath: hivePath, HiveType: hiveType, Category: bk.Category,
			Description: bk.Description, Comment: bk.Comment, KeyPath: keyPath,
			ValueName: name, ValueType: v.TypeString(),
			ValueData: valueDataString(v.ValueData()), LastWriteTimestamp: lw,
			Recursive: bk.Recursive, Deleted: false,
		}
		if err := e.emit(rec); err != nil {
			return n, err
		}
		n++
	}
	// a key with no matching values but a real KeyPath is still a record byakugan
	// keeps (recmd_is_value_record needs a KeyPath, ValueName may be empty) — emit
	// a keystub when the batch didn't name a specific value and the key was empty.
	if bk.ValueName == "" && len(values) == 0 {
		rec := &record{HivePath: hivePath, HiveType: hiveType, Category: bk.Category,
			Description: bk.Description, Comment: bk.Comment, KeyPath: keyPath,
			LastWriteTimestamp: lw, Recursive: bk.Recursive}
		if err := e.emit(rec); err != nil {
			return n, err
		}
		n++
	}
	if bk.Recursive {
		for _, sub := range node.Subkeys() {
			sn, err := emitKey(reg, sub, keyPath+"\\"+sub.Name(), bk, hivePath, hiveType, e)
			if err != nil {
				return n, err
			}
			n += sn
		}
	}
	return n, nil
}

func runHive(hivePath string, b *batch, workDir string, replay bool, e *emitter) (int, error) {
	reg, cleanup, _, err := openHive(hivePath, workDir, replay)
	if err != nil {
		return 0, err
	}
	defer cleanup()
	hiveType := hiveTypeOf(hivePath)
	n := 0
	for _, bk := range b.Keys {
		if bk.HiveType != "" && !strings.EqualFold(bk.HiveType, hiveType) {
			continue // this batch key targets a different hive type
		}
		node := reg.OpenKey(bk.KeyPath)
		if node == nil {
			continue // key absent in this hive
		}
		kn, err := emitKey(reg, node, bk.KeyPath, bk, hivePath, hiveType, e)
		if err != nil {
			return n, err
		}
		n += kn
	}
	return n, nil
}

type emitter struct {
	enc *json.Encoder
	cw  *csv.Writer
}

func (e *emitter) emit(r *record) error {
	if e.cw != nil {
		return e.cw.Write(r.csvRow())
	}
	return e.enc.Encode(r)
}

const regfMagic = "regf"

func isLogFile(p string) bool {
	u := strings.ToUpper(p)
	return strings.HasSuffix(u, ".LOG") || strings.HasSuffix(u, ".LOG1") || strings.HasSuffix(u, ".LOG2")
}

func looksLikeHive(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == regfMagic
}

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
			fmt.Fprintf(os.Stderr, "gore: skipping unreadable %s: %v\n", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
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

const defaultBatch = "/batch/default.reb"

func main() {
	var (
		file    = flag.String("f", "", "single registry hive to process")
		dir     = flag.String("d", "", "directory to scan recursively for registry hives (regf)")
		bn      = flag.String("bn", defaultBatch, "batch definition file (.reb YAML)")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: RECmd_Batch_Output.json)")
		csvDir  = flag.String("csv", "", "directory to write CSV output to instead of JSONL")
		csvF    = flag.String("csvf", "", "CSV file name (default: RECmd_Batch_Output.csv)")
		workDir = flag.String("work-dir", os.TempDir(), "writable dir for the recovered hive during .LOG replay")
		nl      = flag.Bool("nl", false, "no transaction logs: skip dirty-hive .LOG1/.LOG2 replay")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "gore: exactly one of -f <hive> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}
	data, err := os.ReadFile(*bn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gore: batch file %s: %v\n", *bn, err)
		os.Exit(1)
	}
	var b batch
	if err := yaml.Unmarshal(data, &b); err != nil {
		fmt.Fprintf(os.Stderr, "gore: batch file %s: %v\n", *bn, err)
		os.Exit(1)
	}
	if len(b.Keys) == 0 {
		fmt.Fprintf(os.Stderr, "gore: batch file %s has no Keys\n", *bn)
		os.Exit(1)
	}

	dirMode := *dir != ""
	if dirMode {
		if err := os.MkdirAll(*workDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "gore: work dir %s not usable (%v); .LOG replay will fall back to committed hives\n", *workDir, err)
		}
	}
	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gore: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "gore: no files found")
		os.Exit(1)
	}

	var w io.WriteCloser
	e := &emitter{}
	if *csvDir != "" {
		w, err = openOut(*csvDir, *csvF, "RECmd_Batch_Output.csv")
	} else {
		w, err = openOut(*jsonDir, *jsonF, "RECmd_Batch_Output.json")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gore: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if w != os.Stdout {
			w.Close()
		}
	}()
	if *csvDir != "" {
		e.cw = csv.NewWriter(w)
		if err := e.cw.Write(csvHeader); err != nil {
			fmt.Fprintf(os.Stderr, "gore: write: %v\n", err)
			os.Exit(1)
		}
	} else {
		e.enc = json.NewEncoder(w)
	}

	replay := !*nl
	failed, hives, records := 0, 0, 0
	for _, p := range inputs {
		if dirMode && (isLogFile(p) || !looksLikeHive(p)) {
			continue // a hive begins with "regf"; .LOG* are consumed via replay
		}
		n, err := runHive(p, &b, *workDir, replay, e)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "gore: FAILED %s: %v\n", p, err)
			continue
		}
		hives++
		records += n
		if !*quiet {
			fmt.Fprintf(os.Stderr, "gore: %s (%s): %d records\n", p, hiveTypeOf(p), n)
		}
	}
	if e.cw != nil {
		e.cw.Flush()
		if err := e.cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "gore: write: %v\n", err)
			os.Exit(1)
		}
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "gore: %d records across %d hive(s)\n", records, hives)
	}
	if dirMode && hives == 0 && failed == 0 {
		fmt.Fprintf(os.Stderr, "gore: no registry hives found under %s\n", *dir)
		os.Exit(1)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "gore: %d hive(s) failed to parse\n", failed)
		os.Exit(2)
	}
}

// openHive opens the hive at p for reading. When replay is set and sibling
// .LOG1/.LOG2 dirty-hive logs are present it replays them (regparser.RecoverHive)
// into a recovered copy written under workDir (RecoverHive honours $TMPDIR), and
// parses that; otherwise the committed hive. Graceful: a replay error or
// unusable workDir falls back to the committed hive, never a hard fail.
func openHive(p, workDir string, replay bool) (*regparser.Registry, func(), string, error) {
	hf, err := os.Open(p)
	if err != nil {
		return nil, nil, "", err
	}
	var logs []*os.File
	if replay {
		for _, suffix := range []string{".LOG1", ".LOG2"} {
			if lf, lerr := os.Open(p + suffix); lerr == nil {
				logs = append(logs, lf)
			}
		}
	}
	if len(logs) > 0 {
		old := os.Getenv("TMPDIR")
		_ = os.Setenv("TMPDIR", workDir)
		recovered, rerr := regparser.RecoverHive(hf, logs...)
		_ = os.Setenv("TMPDIR", old)
		for _, lf := range logs {
			lf.Close()
		}
		if rerr == nil {
			hf.Close()
			reg, nerr := regparser.NewRegistry(recovered)
			if nerr != nil {
				recovered.Close()
				os.Remove(recovered.Name())
				return nil, nil, "", nerr
			}
			return reg, func() { recovered.Close(); os.Remove(recovered.Name()) }, "recovered via .LOG replay", nil
		}
		reg, nerr := regparser.NewRegistry(hf)
		if nerr != nil {
			hf.Close()
			return nil, nil, "", nerr
		}
		return reg, func() { hf.Close() }, fmt.Sprintf("committed (.LOG replay failed: %v)", rerr), nil
	}
	reg, nerr := regparser.NewRegistry(hf)
	if nerr != nil {
		hf.Close()
		return nil, nil, "", nerr
	}
	return reg, func() { hf.Close() }, "committed", nil
}
