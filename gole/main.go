// gole — Linux-native Windows .lnk (shortcut) parser for the DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's LECmd: it parses .lnk shell-link
// files with parsiya/golnk and emits LECmd's JSON columns (source mtime/atime,
// target MACB times, target path, working dir, arguments, name, relative path,
// file size, header/attribute flags). It runs on Linux with no .NET, no shell
// and no libc (FROM scratch, uid 2000), matching the get-sybers hardening
// contract. Source birth time (LECmd's SourceCreated) is not exposed by the Go
// stdlib on Linux, so that column is dropped rather than emitted always-empty.
//
// Fields golnk does not resolve (a fully-walked TargetIDAbsolutePath from the
// ID list, MFT entry/sequence, tracker MAC) are not emitted — never faked; the
// target path is LinkInfo's LocalBasePath(+CommonPathSuffix), which is what the
// artefact records directly.
//
// Exit codes: 0 = every file parsed; 1 = usage or fatal error; 2 = at least one
// file failed (failures listed on stderr, the rest still emitted).
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
	"syscall"
	"time"

	lnk "github.com/parsiya/golnk"
)

type record struct {
	SourceFile string `json:"SourceFile"`
	// SourceCreated (the .lnk's own birth time) is deliberately absent: Linux
	// does not expose a file birth time through the Go stdlib, so LECmd's
	// SourceCreated column can never be populated here — we drop it rather than
	// emit an always-empty field. SourceModified/SourceAccessed come from the
	// .lnk file's own mtime/atime.
	SourceModified       string `json:"SourceModified"`
	SourceAccessed       string `json:"SourceAccessed"`
	TargetCreated        string `json:"TargetCreated"`
	TargetModified       string `json:"TargetModified"`
	TargetAccessed       string `json:"TargetAccessed"`
	FileSize             uint32 `json:"FileSize"`
	Name                 string `json:"Name,omitempty"`
	RelativePath         string `json:"RelativePath,omitempty"`
	WorkingDirectory     string `json:"WorkingDirectory,omitempty"`
	Arguments            string `json:"Arguments,omitempty"`
	IconLocation         string `json:"IconLocation,omitempty"`
	LocalPath            string `json:"LocalPath,omitempty"`
	CommonPath           string `json:"CommonPath,omitempty"`
	TargetIDAbsolutePath string `json:"TargetIDAbsolutePath,omitempty"`
	HeaderFlags          string `json:"HeaderFlags,omitempty"`
	FileAttributes       string `json:"FileAttributes,omitempty"`
}

var csvHeader = []string{
	"SourceFile", "SourceModified", "SourceAccessed",
	"TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "Name",
	"RelativePath", "WorkingDirectory", "Arguments", "IconLocation", "LocalPath",
	"CommonPath", "TargetIDAbsolutePath", "HeaderFlags", "FileAttributes",
}

func (r *record) csvRow() []string {
	return []string{r.SourceFile, r.SourceModified, r.SourceAccessed,
		r.TargetCreated, r.TargetModified, r.TargetAccessed, strconv.FormatUint(uint64(r.FileSize), 10),
		r.Name, r.RelativePath, r.WorkingDirectory, r.Arguments, r.IconLocation, r.LocalPath,
		r.CommonPath, r.TargetIDAbsolutePath, r.HeaderFlags, r.FileAttributes}
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// setFlags renders a golnk FlagMap (map[string]bool) as a stable, comma-joined
// list of the set flags.
func setFlags(fm lnk.FlagMap) string {
	var on []string
	for k, v := range fm {
		if v {
			on = append(on, k)
		}
	}
	sort.Strings(on)
	return strings.Join(on, ", ")
}

func parseOne(path string) (*record, error) {
	f, err := lnk.File(path)
	if err != nil {
		return nil, err
	}
	local := f.LinkInfo.LocalBasePathUnicode
	if local == "" {
		local = f.LinkInfo.LocalBasePath
	}
	common := f.LinkInfo.CommonPathSuffixUnicode
	if common == "" {
		common = f.LinkInfo.CommonPathSuffix
	}
	rec := &record{
		SourceFile:       path,
		TargetCreated:    ts(f.Header.CreationTime),
		TargetModified:   ts(f.Header.WriteTime),
		TargetAccessed:   ts(f.Header.AccessTime),
		FileSize:         f.Header.TargetFileSize,
		Name:             f.StringData.NameString,
		RelativePath:     f.StringData.RelativePath,
		WorkingDirectory: f.StringData.WorkingDir,
		Arguments:        f.StringData.CommandLineArguments,
		IconLocation:     f.StringData.IconLocation,
		LocalPath:        local,
		CommonPath:       common,
		HeaderFlags:      setFlags(f.Header.LinkFlags),
		FileAttributes:   setFlags(f.Header.FileAttributes),
	}
	// the .lnk file's own fs timestamps (LECmd's Source* columns). mtime is
	// portable; atime comes from the Linux stat_t (the container is Linux). A
	// birth time (SourceCreated) is not exposed by the Go stdlib on Linux, so
	// that column is intentionally not part of the schema — see the record type.
	if st, err := os.Stat(path); err == nil {
		rec.SourceModified = ts(st.ModTime())
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			rec.SourceAccessed = ts(time.Unix(sys.Atim.Unix()))
		}
	}
	return rec, nil
}

const lnkMagic = "\x4c\x00\x00\x00" // ShellLinkHeader HeaderSize = 0x4C

func looksLikeLnk(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == lnkMagic
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
			fmt.Fprintf(os.Stderr, "gole: skipping unreadable %s: %v\n", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() && (strings.EqualFold(filepath.Ext(p), ".lnk") || looksLikeLnk(p)) {
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
		file    = flag.String("f", "", "single .lnk file to parse")
		dir     = flag.String("d", "", "directory to scan recursively for .lnk")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: LECmd_Output.json)")
		csvDir  = flag.String("csv", "", "directory to write CSV output to instead of JSONL")
		csvF    = flag.String("csvf", "", "CSV file name (default: LECmd_Output.csv)")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "gole: exactly one of -f <file> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}
	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gole: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "gole: no .lnk files found")
		os.Exit(1)
	}

	var w io.WriteCloser
	var cw *csv.Writer
	if *csvDir != "" {
		w, err = openOut(*csvDir, *csvF, "LECmd_Output.csv")
	} else {
		w, err = openOut(*jsonDir, *jsonF, "LECmd_Output.json")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gole: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if w != os.Stdout {
			w.Close()
		}
	}()
	if *csvDir != "" {
		cw = csv.NewWriter(w)
		if err := cw.Write(csvHeader); err != nil {
			fmt.Fprintf(os.Stderr, "gole: write: %v\n", err)
			os.Exit(1)
		}
	}
	enc := json.NewEncoder(w)

	failed := 0
	for _, p := range inputs {
		rec, err := parseOne(p)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "gole: FAILED %s: %v\n", p, err)
			continue
		}
		if cw != nil {
			if err := cw.Write(rec.csvRow()); err != nil {
				fmt.Fprintf(os.Stderr, "gole: write: %v\n", err)
				os.Exit(1)
			}
		} else if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "gole: write: %v\n", err)
			os.Exit(1)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "gole: parsed %s -> %s\n", p, rec.LocalPath)
		}
	}
	if cw != nil {
		cw.Flush()
		if err := cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "gole: write: %v\n", err)
			os.Exit(1)
		}
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "gole: %d of %d files failed\n", failed, len(inputs))
		os.Exit(2)
	}
}
