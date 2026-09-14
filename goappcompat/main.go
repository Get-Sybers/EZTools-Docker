// goappcompat — Linux-native Windows AppCompatCache (ShimCache) parser for the
// DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's AppCompatCacheParser: it reads the
// AppCompatCache value from a SYSTEM registry hive with Velociraptor's regparser
// (and its appcompatcache subpackage) and emits one record per shimcache entry —
// the execution-candidate path and its $STANDARD_INFORMATION last-modified time —
// as CSV or JSONL. It runs on Linux with no .NET, no shell and no libc (see
// Dockerfile: FROM scratch, uid 2000), matching the get-sybers hardening
// contract of the other GoDFIR tools.
//
// Columns mirror AppCompatCacheParser: ControlSet, CacheEntryPosition, Path,
// LastModifiedTimeUTC, SourceFile. The .NET tool's Executed/Duplicate columns
// are NOT emitted — regparser's shimcache parser does not expose the
// insertion-flag/dedup state, and a guessed value would be worse than an
// omitted one (never faked). LastModifiedTimeUTC is RFC3339 UTC, empty when the
// entry carries no timestamp.
//
// The regparser appcompatcache parser targets the Win8.1/Win10+ shimcache
// layout (the format on any modern image); a pre-Win8.1 hive whose cache uses
// an older layout yields no entries rather than a mis-parse.
//
// Exit codes: 0 = parsed; 1 = usage or fatal error; 2 = at least one hive failed
// (failures listed on stderr, the rest still emitted).
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
	"time"

	"www.velocidex.com/golang/regparser"
	"www.velocidex.com/golang/regparser/appcompatcache"
)

type record struct {
	ControlSet          int    `json:"ControlSet"`
	CacheEntryPosition  int    `json:"CacheEntryPosition"`
	Path                string `json:"Path"`
	LastModifiedTimeUTC string `json:"LastModifiedTimeUTC,omitempty"`
	SourceFile          string `json:"SourceFile"`
}

var csvHeader = []string{"ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "SourceFile"}

func (r *record) csvRow() []string {
	return []string{
		strconv.Itoa(r.ControlSet), strconv.Itoa(r.CacheEntryPosition),
		r.Path, r.LastModifiedTimeUTC, r.SourceFile,
	}
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

const regfMagic = "regf"

// looksLikeHive peeks the "regf" hive signature so -d picks registry hives out
// of a tree by content (a SYSTEM hive has no "$" so Plaso does not rename it,
// but content-detection keeps -d robust and consistent with the other tools).
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

// currentControlSet reads HKLM\SYSTEM\Select\Current; defaults to 1 when absent.
func currentControlSet(reg *regparser.Registry) int {
	sel := reg.OpenKey("Select")
	if sel != nil {
		for _, v := range sel.Values() {
			if v.ValueName() == "Current" {
				if d := v.ValueData(); d != nil && d.Uint64 > 0 {
					return int(d.Uint64)
				}
			}
		}
	}
	return 1
}

// appCompatCacheData returns the raw AppCompatCache REG_BINARY value bytes for
// the given control set, or nil if the key/value is absent.
func appCompatCacheData(reg *regparser.Registry, cs int) []byte {
	key := fmt.Sprintf("ControlSet%03d\\Control\\Session Manager\\AppCompatCache", cs)
	node := reg.OpenKey(key)
	if node == nil {
		return nil
	}
	for _, v := range node.Values() {
		if v.ValueName() == "AppCompatCache" {
			if d := v.ValueData(); d != nil {
				return d.Data
			}
		}
	}
	return nil
}

// parseHive reads a SYSTEM hive and returns its shimcache entries as records.
func parseHive(path string) ([]*record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, err
	}
	cs := currentControlSet(reg)
	data := appCompatCacheData(reg, cs)
	if data == nil {
		return nil, fmt.Errorf("no ControlSet%03d\\...\\AppCompatCache value (not a SYSTEM hive?)", cs)
	}
	entries := appcompatcache.ParseValueData(data)
	out := make([]*record, 0, len(entries))
	for i, e := range entries {
		out = append(out, &record{
			ControlSet:          cs,
			CacheEntryPosition:  i,
			Path:                e.Name,
			LastModifiedTimeUTC: ts(e.Time),
			SourceFile:          path,
		})
	}
	return out, nil
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
			fmt.Fprintf(os.Stderr, "goappcompat: skipping unreadable %s: %v\n", p, err)
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
		file    = flag.String("f", "", "single SYSTEM hive to parse")
		dir     = flag.String("d", "", "directory to scan recursively for SYSTEM hives (by regf signature)")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: AppCompatCacheParser_Output.jsonl)")
		csvDir  = flag.String("csv", "", "directory to write CSV output to instead of JSONL")
		csvF    = flag.String("csvf", "", "CSV file name (default: AppCompatCacheParser_Output.csv)")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "goappcompat: exactly one of -f <hive> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}

	dirMode := *dir != ""
	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "goappcompat: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "goappcompat: no files found")
		os.Exit(1)
	}

	var w io.WriteCloser
	e := &emitter{}
	if *csvDir != "" {
		w, err = openOut(*csvDir, *csvF, "AppCompatCacheParser_Output.csv")
	} else {
		w, err = openOut(*jsonDir, *jsonF, "AppCompatCacheParser_Output.jsonl")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "goappcompat: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "goappcompat: write: %v\n", err)
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
		recs, err := parseHive(p)
		if err != nil {
			// under -d a regf file that is not a SYSTEM hive (SOFTWARE, NTUSER,
			// ...) simply has no AppCompatCache — skip it silently; only -f (an
			// explicitly named hive) reports the failure.
			if dirMode {
				continue
			}
			failed++
			fmt.Fprintf(os.Stderr, "goappcompat: FAILED %s: %v\n", p, err)
			continue
		}
		for _, r := range recs {
			if err := e.emit(r); err != nil {
				fmt.Fprintf(os.Stderr, "goappcompat: write: %v\n", err)
				os.Exit(1)
			}
		}
		parsed++
		entries += len(recs)
		if !*quiet {
			fmt.Fprintf(os.Stderr, "goappcompat: parsed %s (%d entries)\n", p, len(recs))
		}
	}
	if e.cw != nil {
		e.cw.Flush()
		if err := e.cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "goappcompat: write: %v\n", err)
			os.Exit(1)
		}
	}
	if dirMode && parsed == 0 && failed == 0 {
		fmt.Fprintf(os.Stderr, "goappcompat: no SYSTEM hive with an AppCompatCache found under %s\n", *dir)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "goappcompat: %d entries across %d hive(s)\n", entries, parsed)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "goappcompat: %d hive(s) failed to parse\n", failed)
		os.Exit(2)
	}
}
