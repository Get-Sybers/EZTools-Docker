// goamcache — Linux-native Windows Amcache parser for the DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's AmcacheParser (file-entry mode,
// -i): it parses an Amcache.hve registry hive with Velociraptor's regparser and
// emits one record per program-execution file entry — the facts AmcacheParser's
// CSV carries (the key's last-write time, ProgramId, the SHA-1, full path, name,
// publisher/product/version, size) — as CSV or JSONL. It runs on Linux with no
// .NET, no shell and no libc (see Dockerfile: FROM scratch, uid 2000), matching
// the get-sybers hardening contract of the other GoDFIR tools.
//
// Source key: `Root\InventoryApplicationFile` (the modern Win8+ inventory). The
// SHA-1 in Amcache (`FileId`) is a 44-char string with a "0000" prefix — it is
// stripped to the bare 40-hex hash, exactly as byakugan's plaso amcache map does.
//
// Dirty-hive .LOG1/.LOG2 transaction logs ARE replayed (regparser.RecoverHive)
// when they sit beside the hive, matching AmcacheParser's fidelity. Replay writes
// a recovered copy under --work-dir (default $TMPDIR), which must be writable —
// the container rootfs is read-only, so the pipeline mounts a tmpfs there. If the
// logs are absent, or replay fails, or the work dir is not writable, it falls
// back to the committed hive with a one-line stderr note (never a hard fail).
// Timestamps are RFC3339 (UTC), empty when absent.
//
// Exit codes: 0 = every hive parsed; 1 = usage or fatal error; 2 = at least one
// file failed to parse (failures listed on stderr, the rest still emitted).
package main

import (
	"encoding/csv"
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

	"www.velocidex.com/golang/regparser"
)

// record mirrors the columns AmcacheParser's file-entry CSV carries (the subset
// the InventoryApplicationFile key supplies).
type record struct {
	FileKeyLastWriteTimestamp string `json:"FileKeyLastWriteTimestamp,omitempty"`
	ProgramId                 string `json:"ProgramId,omitempty"`
	SHA1                      string `json:"SHA1,omitempty"`
	FullPath                  string `json:"FullPath,omitempty"`
	Name                      string `json:"Name,omitempty"`
	FileExtension             string `json:"FileExtension,omitempty"`
	Publisher                 string `json:"Publisher,omitempty"`
	ProductName               string `json:"ProductName,omitempty"`
	Version                   string `json:"Version,omitempty"`
	ProductVersion            string `json:"ProductVersion,omitempty"`
	BinFileVersion            string `json:"BinFileVersion,omitempty"`
	BinaryType                string `json:"BinaryType,omitempty"`
	LinkDate                  string `json:"LinkDate,omitempty"`
	Size                      int64  `json:"Size"`
}

var csvHeader = []string{
	"FileKeyLastWriteTimestamp", "ProgramId", "SHA1", "FullPath", "Name", "FileExtension",
	"Publisher", "ProductName", "Version", "ProductVersion", "BinFileVersion", "BinaryType",
	"LinkDate", "Size",
}

func (r *record) csvRow() []string {
	return []string{
		r.FileKeyLastWriteTimestamp, r.ProgramId, r.SHA1, r.FullPath, r.Name, r.FileExtension,
		r.Publisher, r.ProductName, r.Version, r.ProductVersion, r.BinFileVersion, r.BinaryType,
		r.LinkDate, strconv.FormatInt(r.Size, 10),
	}
}

// valueMap indexes a key's values by lower-cased name for easy lookup.
func valueMap(node *regparser.CM_KEY_NODE) map[string]*regparser.ValueData {
	m := map[string]*regparser.ValueData{}
	for _, v := range node.Values() {
		if d := v.ValueData(); d != nil {
			m[strings.ToLower(v.ValueName())] = d
		}
	}
	return m
}

func vstr(m map[string]*regparser.ValueData, key string) string {
	if d := m[strings.ToLower(key)]; d != nil {
		return strings.TrimRight(d.String, "\x00")
	}
	return ""
}

func vint(m map[string]*regparser.ValueData, key string) int64 {
	if d := m[strings.ToLower(key)]; d != nil {
		return int64(d.Uint64)
	}
	return 0
}

// stripSHA1 drops Amcache's "0000" FileId prefix, yielding the bare 40-hex hash.
func stripSHA1(fileID string) string {
	s := strings.TrimSpace(fileID)
	if len(s) == 44 && strings.HasPrefix(s, "0000") {
		return s[4:]
	}
	return s
}

const amcacheKey = `Root\InventoryApplicationFile`

func entryToRecord(sub *regparser.CM_KEY_NODE) *record {
	m := valueMap(sub)
	name := vstr(m, "Name")
	full := vstr(m, "LowerCaseLongPath")
	ext := vstr(m, "FileExtension")
	if ext == "" {
		base := name
		if base == "" {
			base = full
		}
		ext = strings.ToLower(filepath.Ext(base))
	}
	ts := ""
	if ft := sub.LastWriteTime(); ft != nil && !ft.Time.IsZero() {
		ts = ft.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return &record{
		FileKeyLastWriteTimestamp: ts,
		ProgramId:                 vstr(m, "ProgramId"),
		SHA1:                      stripSHA1(vstr(m, "FileId")),
		FullPath:                  full,
		Name:                      name,
		FileExtension:             ext,
		Publisher:                 vstr(m, "Publisher"),
		ProductName:               vstr(m, "ProductName"),
		Version:                   vstr(m, "Version"),
		ProductVersion:            vstr(m, "ProductVersion"),
		BinFileVersion:            vstr(m, "BinFileVersion"),
		BinaryType:                vstr(m, "BinaryType"),
		LinkDate:                  vstr(m, "LinkDate"),
		Size:                      vint(m, "Size"),
	}
}

// emitter writes one record, JSONL or CSV.
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

// openHive opens the hive at `p` for reading. When sibling .LOG1/.LOG2 dirty-hive
// transaction logs are present it replays them (regparser.RecoverHive) into a
// recovered copy (written under $TMPDIR — the caller points that at --work-dir)
// and returns that; otherwise it returns the committed hive. Returns a cleanup
// to close (and delete any recovered copy), plus a note of which path was taken.
// Replay is best-effort: on any failure it falls back to the committed hive.
func openHive(p string) (*regparser.Registry, func(), string, error) {
	hf, err := os.Open(p)
	if err != nil {
		return nil, nil, "", err
	}
	var logs []*os.File
	for _, suffix := range []string{".LOG1", ".LOG2"} {
		if lf, lerr := os.Open(p + suffix); lerr == nil {
			logs = append(logs, lf)
		}
	}
	if len(logs) > 0 {
		recovered, rerr := regparser.RecoverHive(hf, logs...)
		for _, lf := range logs {
			lf.Close()
		}
		if rerr == nil {
			hf.Close() // done with the committed hive; parse the recovered copy
			reg, nerr := regparser.NewRegistry(recovered)
			if nerr != nil {
				recovered.Close()
				os.Remove(recovered.Name())
				return nil, nil, "", nerr
			}
			return reg, func() { recovered.Close(); os.Remove(recovered.Name()) },
				"recovered via .LOG replay", nil
		}
		// replay failed — fall back to the committed hive, never hard-fail
		reg, nerr := regparser.NewRegistry(hf)
		if nerr != nil {
			hf.Close()
			return nil, nil, "", nerr
		}
		return reg, func() { hf.Close() },
			fmt.Sprintf("committed (.LOG replay failed: %v)", rerr), nil
	}
	reg, nerr := regparser.NewRegistry(hf)
	if nerr != nil {
		hf.Close()
		return nil, nil, "", nerr
	}
	return reg, func() { hf.Close() }, "committed (no .LOG files)", nil
}

// parseHive emits one record per InventoryApplicationFile entry in the hive at
// `p`. `found` is true only when the hive actually holds the Amcache key — a
// plain SYSTEM/SOFTWARE regf hive returns (0, false, ...) so callers don't count
// it as an Amcache source.
func parseHive(p string, e *emitter) (n int, found bool, note string, err error) {
	reg, cleanup, note, err := openHive(p)
	if err != nil {
		return 0, false, note, err
	}
	defer cleanup()
	root := reg.OpenKey(amcacheKey)
	if root == nil {
		return 0, false, note, nil // a regf hive, but not an Amcache hive
	}
	for _, sub := range root.Subkeys() {
		if err := e.emit(entryToRecord(sub)); err != nil {
			return n, true, note, err
		}
		n++
	}
	return n, true, note, nil
}

const hiveMagic = "regf"

// looksLikeHive peeks the "regf" registry-hive signature so -d can find the hive
// by content. (Amcache.hve has no "$", so Plaso does not rename it — but content
// detection is robust regardless.)
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
	return string(hdr[:]) == hiveMagic
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
			fmt.Fprintf(os.Stderr, "goamcache: skipping unreadable %s: %v\n", p, err)
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

func main() {
	var (
		file    = flag.String("f", "", "single Amcache.hve to parse")
		dir     = flag.String("d", "", "directory to scan recursively for a hive (by regf signature)")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: Amcache_Output.jsonl)")
		csvDir  = flag.String("csv", "", "directory to write CSV output to instead of JSONL")
		csvF    = flag.String("csvf", "", "CSV file name (default: Amcache_Output.csv)")
		workDir = flag.String("work-dir", os.TempDir(), "writable dir for the recovered hive when replaying .LOG files")
		_       = flag.Bool("i", false, "include file entries (accepted for AmcacheParser compatibility; file entries are always emitted)")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "goamcache: exactly one of -f <file> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}

	// regparser.RecoverHive writes its recovered copy under os.TempDir(), which
	// honours $TMPDIR — point that at --work-dir so replay lands on a writable
	// mount (the container rootfs is read-only). Best-effort: if the dir can't be
	// made, replay will just fail and fall back to the committed hive.
	if err := os.MkdirAll(*workDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "goamcache: work dir %s not usable (%v); .LOG replay will fall back to committed hives\n", *workDir, err)
	}
	os.Setenv("TMPDIR", *workDir)

	dirMode := *dir != ""
	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "goamcache: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "goamcache: no files found")
		os.Exit(1)
	}

	var w io.WriteCloser
	e := &emitter{}
	if *csvDir != "" {
		w, err = openOut(*csvDir, *csvF, "Amcache_Output.csv")
	} else {
		w, err = openOut(*jsonDir, *jsonF, "Amcache_Output.jsonl")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "goamcache: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "goamcache: write: %v\n", err)
			os.Exit(1)
		}
	} else {
		e.enc = json.NewEncoder(w)
	}

	failed, sources, entries := 0, 0, 0
	for _, p := range inputs {
		if dirMode && !looksLikeHive(p) {
			continue // -d: pick registry hives out of the tree by their regf signature
		}
		n, found, note, err := parseHive(p, e)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "goamcache: FAILED %s: %v\n", p, err)
			continue
		}
		if !found {
			// a regf hive without the Amcache key (SYSTEM/SOFTWARE, wrong hive):
			// not an Amcache source — never counted or logged as "parsed"
			if !dirMode && !*quiet {
				fmt.Fprintf(os.Stderr, "goamcache: %s has no %s key (not an Amcache hive)\n", p, amcacheKey)
			}
			continue
		}
		sources++
		entries += n
		if !*quiet {
			fmt.Fprintf(os.Stderr, "goamcache: parsed %s (%d entries, %s)\n", p, n, note)
		}
	}
	if e.cw != nil {
		e.cw.Flush()
		if err := e.cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "goamcache: write: %v\n", err)
			os.Exit(1)
		}
	}
	if dirMode && sources == 0 && failed == 0 {
		fmt.Fprintf(os.Stderr, "goamcache: no Amcache hive found under %s\n", *dir)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "goamcache: %d entries across %d Amcache hive(s)\n", entries, sources)
	}
	// A run that scanned input but emitted nothing is not a silent success:
	// exit non-zero so an empty result (a non-Amcache -f target, or hives that
	// yielded no entries) is caught rather than passing as done.
	if entries == 0 && failed == 0 {
		fmt.Fprintln(os.Stderr, "goamcache: no Amcache records emitted")
		os.Exit(1)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "goamcache: %d file(s) failed to parse\n", failed)
		os.Exit(2)
	}
}
