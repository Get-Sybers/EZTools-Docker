// rbcmd — Linux-native Windows Recycle Bin ($I) parser for the DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's RBCmd: it parses the modern
// Recycle Bin metadata files ($I<id>, one per deleted item, that pair with the
// $R<id> payload) and emits the same facts — original path, logical size,
// deletion time — as CSV or JSONL. It runs on Linux with no .NET, no shell and
// no libc (see Dockerfile: FROM scratch, uid 2000), matching the get-sybers
// hardening contract of the prefetch/esedump Go substitutes.
//
// Two on-disk layouts are handled (both little-endian):
//   - v1 (Windows Vista–8.0): [int64 version=1][int64 size][FILETIME deleted]
//     [520 bytes UTF-16LE path, fixed 260 wchar, null-terminated] = 544 bytes.
//   - v2 (Windows 8.1/10/11):  [int64 version=2][int64 size][FILETIME deleted]
//     [uint32 nameLen (wchar, incl NUL)][nameLen*2 bytes UTF-16LE path].
//
// The legacy XP INFO2 container is NOT handled (RBCmd's "INFO2" FileType) — it
// is obsolete and not in the pipeline's extraction filter; such a file is
// reported as a parse failure rather than mis-read.
//
// Output columns mirror RBCmd: SourceName, FileType, FileName, FileSize,
// DeletedOn. DeletedOn is rendered RFC3339 UTC (RBCmd renders local/UTC per its
// --dt flag; the pipeline consumes the field, not its exact rendering).
//
// Exit codes: 0 = every file parsed; 1 = usage or fatal error; 2 = at least one
// file failed to parse (failures listed on stderr, the rest still emitted).
package main

import (
	"encoding/binary"
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
	"unicode/utf16"
)

type record struct {
	SourceName string `json:"SourceName"`
	FileType   string `json:"FileType"`
	FileName   string `json:"FileName"`
	FileSize   int64  `json:"FileSize"`
	DeletedOn  string `json:"DeletedOn"`
}

// filetimeToTime converts a Windows FILETIME (100-ns ticks since 1601-01-01 UTC)
// to a Go UTC time. 11644473600 is the 1601→1970 epoch gap in seconds.
func filetimeToTime(ft int64) time.Time {
	const ticksPerSecond = 10_000_000
	const epochGap = 11644473600
	secs := ft/ticksPerSecond - epochGap
	nsec := (ft % ticksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}

// utf16leString decodes a little-endian UTF-16 buffer up to the first NUL, or
// the whole buffer if unterminated.
func utf16leString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func parseOne(path string) (*record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("too small (%d bytes) to be a $I record", len(data))
	}
	version := int64(binary.LittleEndian.Uint64(data[0:8]))
	size := int64(binary.LittleEndian.Uint64(data[8:16]))
	deleted := int64(binary.LittleEndian.Uint64(data[16:24]))

	var name string
	switch version {
	case 1:
		// fixed 260-wchar (520-byte) path field
		if len(data) < 24+520 {
			return nil, fmt.Errorf("v1 $I truncated: %d bytes, want >= 544", len(data))
		}
		name = utf16leString(data[24 : 24+520])
	case 2:
		if len(data) < 28 {
			return nil, fmt.Errorf("v2 $I truncated: %d bytes, want >= 28", len(data))
		}
		nameLen := int(binary.LittleEndian.Uint32(data[24:28])) // wchar count incl NUL
		want := 28 + nameLen*2
		if nameLen <= 0 || len(data) < want {
			return nil, fmt.Errorf("v2 $I name length %d overruns %d-byte file", nameLen, len(data))
		}
		name = utf16leString(data[28:want])
	default:
		return nil, fmt.Errorf("unknown $I version %d (only 1 and 2 are supported)", version)
	}

	return &record{
		SourceName: path,
		FileType:   "$I",
		FileName:   name,
		FileSize:   size,
		DeletedOn:  filetimeToTime(deleted).Format(time.RFC3339),
	}, nil
}

// collectInputs returns the $I files to parse: a single -f file, or every file
// under -d whose basename starts with "$I" (the modern Recycle Bin metadata
// naming, e.g. $IXXXXXX.ext). Unreadable subtrees under -d are skipped with a
// note; an unreadable root is fatal.
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
			fmt.Fprintf(os.Stderr, "rbcmd: skipping unreadable %s: %v\n", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() && strings.HasPrefix(filepath.Base(p), "$I") {
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
		file    = flag.String("f", "", "single $I file to parse")
		dir     = flag.String("d", "", "directory to scan recursively for $I* files")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: RBCmd_Output.jsonl)")
		csvDir  = flag.String("csv", "", "directory to write CSV output to instead of JSONL")
		csvF    = flag.String("csvf", "", "CSV file name (default: RBCmd_Output.csv)")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "rbcmd: exactly one of -f <file> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}

	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rbcmd: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "rbcmd: no $I files found")
		os.Exit(1)
	}

	var w io.WriteCloser
	var cw *csv.Writer
	if *csvDir != "" {
		w, err = openOut(*csvDir, *csvF, "RBCmd_Output.csv")
	} else {
		w, err = openOut(*jsonDir, *jsonF, "RBCmd_Output.jsonl")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "rbcmd: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if w != os.Stdout {
			w.Close()
		}
	}()

	if *csvDir != "" {
		cw = csv.NewWriter(w)
		if err := cw.Write([]string{"SourceName", "FileType", "FileName", "FileSize", "DeletedOn"}); err != nil {
			fmt.Fprintf(os.Stderr, "rbcmd: write: %v\n", err)
			os.Exit(1)
		}
	}

	enc := json.NewEncoder(w)
	failed := 0
	for _, p := range inputs {
		rec, err := parseOne(p)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "rbcmd: FAILED %s: %v\n", p, err)
			continue
		}
		if cw != nil {
			if err := cw.Write([]string{rec.SourceName, rec.FileType, rec.FileName,
				strconv.FormatInt(rec.FileSize, 10), rec.DeletedOn}); err != nil {
				fmt.Fprintf(os.Stderr, "rbcmd: write: %v\n", err)
				os.Exit(1)
			}
		} else if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "rbcmd: write: %v\n", err)
			os.Exit(1)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "rbcmd: parsed %s (%s, %d bytes)\n", p, rec.FileName, rec.FileSize)
		}
	}
	if cw != nil {
		cw.Flush()
		if err := cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "rbcmd: write: %v\n", err)
			os.Exit(1)
		}
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "rbcmd: %d of %d files failed\n", failed, len(inputs))
		os.Exit(2)
	}
}
