package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

// filetimeOf is the inverse of filetimeToTime — build a FILETIME for a known
// instant so the round-trip is exact.
func filetimeOf(t time.Time) int64 {
	const ticksPerSecond = 10_000_000
	const epochGap = 11644473600
	return (t.Unix()+epochGap)*ticksPerSecond + int64(t.Nanosecond())/100
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func makeV1(size int64, deleted time.Time, path string) []byte {
	b := make([]byte, 24+520)
	binary.LittleEndian.PutUint64(b[0:8], 1)
	binary.LittleEndian.PutUint64(b[8:16], uint64(size))
	binary.LittleEndian.PutUint64(b[16:24], uint64(filetimeOf(deleted)))
	copy(b[24:24+520], utf16le(path)) // remainder stays NUL — fixed 260-wchar field
	return b
}

func makeV2(size int64, deleted time.Time, path string) []byte {
	name := append(utf16le(path), 0, 0) // NUL-terminated
	nameLen := len(name) / 2            // wchar count incl NUL
	b := make([]byte, 28+len(name))
	binary.LittleEndian.PutUint64(b[0:8], 2)
	binary.LittleEndian.PutUint64(b[8:16], uint64(size))
	binary.LittleEndian.PutUint64(b[16:24], uint64(filetimeOf(deleted)))
	binary.LittleEndian.PutUint32(b[24:28], uint32(nameLen))
	copy(b[28:], name)
	return b
}

func TestParseV1(t *testing.T) {
	when := time.Date(2018, 1, 30, 15, 30, 7, 0, time.UTC)
	p := filepath.Join(t.TempDir(), "$IABCDEF.txt")
	if err := os.WriteFile(p, makeV1(78706, when, `C:\Users\jo\secret.docx`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := parseOne(p)
	if err != nil {
		t.Fatalf("parseOne: %v", err)
	}
	if rec.FileName != `C:\Users\jo\secret.docx` {
		t.Errorf("FileName = %q", rec.FileName)
	}
	if rec.FileSize != 78706 {
		t.Errorf("FileSize = %d", rec.FileSize)
	}
	if rec.DeletedOn != "2018-01-30T15:30:07Z" {
		t.Errorf("DeletedOn = %q", rec.DeletedOn)
	}
	if rec.FileType != "$I" {
		t.Errorf("FileType = %q", rec.FileType)
	}
}

func TestParseV2(t *testing.T) {
	when := time.Date(2020, 9, 16, 13, 14, 30, 0, time.UTC)
	p := filepath.Join(t.TempDir(), "$I123456")
	if err := os.WriteFile(p, makeV2(1024, when, `D:\data\こんにちは.bin`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := parseOne(p)
	if err != nil {
		t.Fatalf("parseOne: %v", err)
	}
	if rec.FileName != `D:\data\こんにちは.bin` { // UTF-16 incl. non-ASCII survives
		t.Errorf("FileName = %q", rec.FileName)
	}
	if rec.FileSize != 1024 {
		t.Errorf("FileSize = %d", rec.FileSize)
	}
	if rec.DeletedOn != "2020-09-16T13:14:30Z" {
		t.Errorf("DeletedOn = %q", rec.DeletedOn)
	}
}

func TestParseRejectsUnknownVersionAndTruncation(t *testing.T) {
	dir := t.TempDir()
	// unknown version
	bad := make([]byte, 544)
	binary.LittleEndian.PutUint64(bad[0:8], 99)
	badPath := filepath.Join(dir, "$IBAD")
	mustWrite(t, badPath, bad)
	if _, err := parseOne(badPath); err == nil {
		t.Error("expected error for unknown version")
	}
	// truncated v2 (name length overruns the file)
	v2 := make([]byte, 28+4)
	binary.LittleEndian.PutUint64(v2[0:8], 2)
	binary.LittleEndian.PutUint32(v2[24:28], 999)
	truncPath := filepath.Join(dir, "$ITRUNC")
	mustWrite(t, truncPath, v2)
	if _, err := parseOne(truncPath); err == nil {
		t.Error("expected error for overrunning v2 name length")
	}
}

func TestDirScanDetectsRecordsByHeaderNotName(t *testing.T) {
	dir := t.TempDir()
	when := time.Date(2025, 3, 18, 5, 40, 22, 0, time.UTC)
	// a raw-mount $I name, a Plaso-renamed $ -> _ name, and non-$I files that
	// share the tree (desktop.ini, a $R payload, an unrelated file)
	mustWrite(t, filepath.Join(dir, "$IRAWNAME.docx"), makeV2(10, when, `C:\a.docx`))
	mustWrite(t, filepath.Join(dir, "_IPLASO.lnk"), makeV1(20, when, `C:\b.lnk`)) // plaso rename
	mustWrite(t, filepath.Join(dir, "desktop.ini"), []byte("[.ShellClassInfo]\n"))
	mustWrite(t, filepath.Join(dir, "$RPAYLOAD.docx"), []byte("real file contents, not a header"))
	mustWrite(t, filepath.Join(dir, "notes.txt"), []byte("nope"))

	files, err := collectInputs("", dir)
	if err != nil {
		t.Fatal(err)
	}
	// collectInputs returns every file; the header check picks the two records
	var detected []string
	for _, p := range files {
		if peekLooksLikeRecord(p) {
			if _, err := parseOne(p); err != nil {
				t.Errorf("header-detected %s but parse failed: %v", p, err)
			}
			detected = append(detected, filepath.Base(p))
		}
	}
	if len(detected) != 2 {
		t.Errorf("detected %d $I records, want 2 ($IRAWNAME.docx + _IPLASO.lnk): %v", len(detected), detected)
	}
}
