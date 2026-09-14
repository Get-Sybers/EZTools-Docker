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
// LIMITATION: regparser reads the committed hive only — it does NOT replay the
// .LOG1/.LOG2 dirty-hive transaction logs, so entries still pending in the logs
// (which AmcacheParser replays) are not seen. This is stated, not faked; the
// base hive carries the great majority of entries. Timestamps are RFC3339 (UTC),
// empty when absent.
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

// parseFile reads the Amcache hive at `p`, emitting one record per
// InventoryApplicationFile entry; returns the number emitted.
func parseFile(p string, e *emitter) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return 0, err
	}
	root := reg.OpenKey(amcacheKey)
	if root == nil {
		// Not a fatal parse error — an older hive without the modern inventory
		// key simply yields nothing here (documented limitation).
		return 0, nil
	}
	n := 0
	for _, sub := range root.Subkeys() {
		if err := e.emit(entryToRecord(sub)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
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
		_       = flag.Bool("i", false, "include file entries (accepted for AmcacheParser compatibility; file entries are always emitted)")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "goamcache: exactly one of -f <file> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}

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

	failed, parsed, entries := 0, 0, 0
	for _, p := range inputs {
		if dirMode && !looksLikeHive(p) {
			continue // -d: pick registry hives out of the tree by their regf signature
		}
		n, err := parseFile(p, e)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "goamcache: FAILED %s: %v\n", p, err)
			continue
		}
		parsed++
		entries += n
		if !*quiet {
			fmt.Fprintf(os.Stderr, "goamcache: parsed %s (%d entries)\n", p, n)
		}
	}
	if e.cw != nil {
		e.cw.Flush()
		if err := e.cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "goamcache: write: %v\n", err)
			os.Exit(1)
		}
	}
	if dirMode && parsed == 0 && failed == 0 {
		fmt.Fprintf(os.Stderr, "goamcache: no registry hive found under %s\n", *dir)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "goamcache: %d entries across %d hive(s)\n", entries, parsed)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "goamcache: %d file(s) failed to parse\n", failed)
		os.Exit(2)
	}
}
