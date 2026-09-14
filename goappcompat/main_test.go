package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestTSZeroAndValue(t *testing.T) {
	if got := ts(time.Time{}); got != "" {
		t.Errorf("zero time -> %q, want empty", got)
	}
	if got := ts(time.Date(2023, 5, 5, 12, 22, 18, 0, time.UTC)); got != "2023-05-05T12:22:18Z" {
		t.Errorf("ts = %q", got)
	}
}

func TestCsvRowMatchesHeaderLen(t *testing.T) {
	if len((&record{}).csvRow()) != len(csvHeader) {
		t.Errorf("csvRow %d cols, header %d", len((&record{}).csvRow()), len(csvHeader))
	}
}

func TestLooksLikeHiveByRegfSignature(t *testing.T) {
	dir := t.TempDir()
	hive := filepath.Join(dir, "SYSTEM")
	mustWrite(t, hive, append([]byte("regf"), make([]byte, 100)...))
	if !looksLikeHive(hive) {
		t.Error("regf-signature file not detected as a hive")
	}
	notHive := filepath.Join(dir, "notes.txt")
	mustWrite(t, notHive, []byte("not a hive"))
	if looksLikeHive(notHive) {
		t.Error("non-hive wrongly detected")
	}
	tiny := filepath.Join(dir, "x")
	mustWrite(t, tiny, []byte("re"))
	if looksLikeHive(tiny) {
		t.Error("too-short file wrongly detected")
	}
}
