package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTSZeroAndValue(t *testing.T) {
	if got := ts(time.Time{}); got != "" {
		t.Errorf("zero time -> %q, want empty", got)
	}
	when := time.Date(2025, 2, 24, 19, 24, 9, 0, time.UTC)
	if got := ts(when); got != "2025-02-24T19:24:09Z" {
		t.Errorf("ts = %q", got)
	}
}

func TestCsvRowMatchesHeaderLen(t *testing.T) {
	r := &record{}
	if len(r.csvRow()) != len(csvHeader) {
		t.Errorf("csvRow has %d cols, header has %d", len(r.csvRow()), len(csvHeader))
	}
}

func TestLooksLikeMFTByHeader(t *testing.T) {
	dir := t.TempDir()
	// a $MFT / plaso-renamed _MFT begins with the "FILE" record signature
	mft := filepath.Join(dir, "_MFT")
	if err := os.WriteFile(mft, append([]byte("FILE"), make([]byte, 1020)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if !looksLikeMFT(mft) {
		t.Error("FILE-signature file not detected as $MFT")
	}
	// a registry hive ("regf") or short file is not an $MFT
	hive := filepath.Join(dir, "SYSTEM")
	if err := os.WriteFile(hive, []byte("regf....."), 0o644); err != nil {
		t.Fatal(err)
	}
	if looksLikeMFT(hive) {
		t.Error("non-$MFT file wrongly detected")
	}
	tiny := filepath.Join(dir, "x")
	if err := os.WriteFile(tiny, []byte("FI"), 0o644); err != nil {
		t.Fatal(err)
	}
	if looksLikeMFT(tiny) {
		t.Error("too-short file wrongly detected")
	}
}

// parseFile must handle a minimal well-formed 1 KiB FILE record without error
// (0 emitted highlights is fine — the point is the go-ntfs integration parses,
// end-to-end coverage over a real $MFT is in the pipeline validation).
func TestParseMinimalRecordNoError(t *testing.T) {
	rec := make([]byte, 1024)
	copy(rec, "FILE")
	binary.LittleEndian.PutUint16(rec[24:], 1024) // mft_entry_size
	binary.LittleEndian.PutUint16(rec[28:], 1024) // mft_entry_allocated
	p := filepath.Join(t.TempDir(), "_MFT")
	if err := os.WriteFile(p, rec, 0o644); err != nil {
		t.Fatal(err)
	}
	e := &emitter{enc: json.NewEncoder(io.Discard)}
	if _, err := parseFile(p, 1024, 4096, e); err != nil {
		t.Errorf("parseFile on a minimal FILE record: %v", err)
	}
}
