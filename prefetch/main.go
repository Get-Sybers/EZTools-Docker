// prefetch_dump — Linux-native Windows Prefetch parser for the DX_DFIR pipeline.
//
// PECmd cannot run on non-Windows hosts: its startup guard exits ("Non-Windows
// platforms not supported due to the need to load decompression specific
// Windows libraries!") because the upstream Prefetch library P/Invokes
// ntdll!RtlDecompressBufferEx for Win8+/Win10 MAM (LZXpress-Huffman) files.
// This tool uses Velociraptor's go-prefetch, which carries a pure-Go
// LZXpress-Huffman implementation, so XP-era through Win11 prefetch — MAM
// compressed included — parse on Linux.
//
// Output is JSONL (one object per .pf) or CSV. Field mapping vs PECmd:
// Executable/RunCount/LastRun/PreviousRunN/FilesAccessed/Hash/Version carry
// the same artifact facts; volume info blocks are not emitted (not exposed by
// go-prefetch). SourceFilename and SourceModified come from the input file.
//
// Exit codes: 0 = every file parsed; 1 = usage or fatal error; 2 = at least
// one file failed to parse (failures listed on stderr, the rest still emitted).
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
	"time"

	prefetch "www.velocidex.com/golang/go-prefetch"
)

type record struct {
	SourceFilename string   `json:"SourceFilename"`
	SourceModified string   `json:"SourceModified"`
	Executable     string   `json:"Executable"`
	Path           string   `json:"Path,omitempty"`
	Hash           string   `json:"Hash"`
	Version        string   `json:"Version"`
	FileSize       uint32   `json:"FileSize"`
	RunCount       uint32   `json:"RunCount"`
	LastRun        string   `json:"LastRun,omitempty"`
	PreviousRuns   []string `json:"PreviousRuns,omitempty"`
	FilesAccessed  []string `json:"FilesAccessed"`
}

func parseOne(path string) (*record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := prefetch.LoadPrefetch(f)
	if err != nil {
		return nil, err
	}

	rec := &record{
		SourceFilename: path,
		Executable:     info.Executable,
		Path:           info.Path,
		Hash:           info.Hash,
		Version:        info.Version,
		FileSize:       info.FileSize,
		RunCount:       info.RunCount,
		FilesAccessed:  info.FilesAccessed,
	}
	if st, err := f.Stat(); err == nil {
		rec.SourceModified = st.ModTime().UTC().Format(time.RFC3339)
	}

	// go-prefetch returns run times newest-first for Win8+; normalise anyway.
	runs := append([]time.Time(nil), info.LastRunTimes...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].After(runs[j]) })
	if len(runs) > 0 {
		rec.LastRun = runs[0].UTC().Format(time.RFC3339)
		for _, t := range runs[1:] {
			rec.PreviousRuns = append(rec.PreviousRuns, t.UTC().Format(time.RFC3339))
		}
	}
	return rec, nil
}

func collectInputs(file, dir string) ([]string, error) {
	if file != "" {
		return []string{file}, nil
	}
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(p), ".pf") {
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
		file    = flag.String("f", "", "single prefetch file to parse")
		dir     = flag.String("d", "", "directory to scan recursively for *.pf")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: PrefetchDump_Output.jsonl)")
		csvDir  = flag.String("csv", "", "directory to write CSV output to instead of JSONL")
		csvF    = flag.String("csvf", "", "CSV file name (default: PrefetchDump_Output.csv)")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "prefetch_dump: exactly one of -f <file> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}

	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prefetch_dump: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "prefetch_dump: no .pf files found")
		os.Exit(1)
	}

	var w io.WriteCloser
	var cw *csv.Writer
	if *csvDir != "" {
		w, err = openOut(*csvDir, *csvF, "PrefetchDump_Output.csv")
	} else {
		w, err = openOut(*jsonDir, *jsonF, "PrefetchDump_Output.jsonl")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "prefetch_dump: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if w != os.Stdout {
			w.Close()
		}
	}()

	if *csvDir != "" {
		cw = csv.NewWriter(w)
		_ = cw.Write([]string{"SourceFilename", "SourceModified", "Executable", "Path",
			"Hash", "Version", "FileSize", "RunCount", "LastRun", "PreviousRuns", "FilesAccessed"})
	}

	enc := json.NewEncoder(w)
	failed := 0
	for _, p := range inputs {
		rec, err := parseOne(p)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "prefetch_dump: FAILED %s: %v\n", p, err)
			continue
		}
		if cw != nil {
			_ = cw.Write([]string{rec.SourceFilename, rec.SourceModified, rec.Executable,
				rec.Path, rec.Hash, rec.Version, strconv.FormatUint(uint64(rec.FileSize), 10),
				strconv.FormatUint(uint64(rec.RunCount), 10), rec.LastRun,
				strings.Join(rec.PreviousRuns, "|"), strings.Join(rec.FilesAccessed, "|")})
		} else if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "prefetch_dump: write: %v\n", err)
			os.Exit(1)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "prefetch_dump: parsed %s (%s, run count %d)\n",
				p, rec.Version, rec.RunCount)
		}
	}
	if cw != nil {
		cw.Flush()
		if err := cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "prefetch_dump: write: %v\n", err)
			os.Exit(1)
		}
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "prefetch_dump: %d of %d files failed\n", failed, len(inputs))
		os.Exit(2)
	}
}
