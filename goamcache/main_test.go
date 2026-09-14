package main

import (
	"os"
	"path/filepath"
	"testing"
)

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestStripSHA1(t *testing.T) {
	// Amcache FileId is "0000" + 40-hex; strip to the bare hash
	full := "0000" + "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
	if got := stripSHA1(full); got != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Errorf("stripSHA1 = %q", got)
	}
	// a value that is not the 44-char prefixed form is left as-is
	if got := stripSHA1("deadbeef"); got != "deadbeef" {
		t.Errorf("stripSHA1(short) = %q", got)
	}
	if got := stripSHA1(""); got != "" {
		t.Errorf("stripSHA1(empty) = %q", got)
	}
}

func TestCsvRowMatchesHeaderLen(t *testing.T) {
	r := &record{}
	if len(r.csvRow()) != len(csvHeader) {
		t.Errorf("csvRow has %d cols, header has %d", len(r.csvRow()), len(csvHeader))
	}
}

func TestLooksLikeHiveByHeader(t *testing.T) {
	dir := t.TempDir()
	hive := filepath.Join(dir, "Amcache.hve")
	mustWrite(t, hive, append([]byte("regf"), make([]byte, 512)...))
	if !looksLikeHive(hive) {
		t.Error("regf-signature file not detected as a hive")
	}
	notHive := filepath.Join(dir, "notes.txt")
	mustWrite(t, notHive, []byte("plain text, not a hive"))
	if looksLikeHive(notHive) {
		t.Error("non-hive file wrongly detected")
	}
	tiny := filepath.Join(dir, "x")
	mustWrite(t, tiny, []byte("re"))
	if looksLikeHive(tiny) {
		t.Error("too-short file wrongly detected")
	}
}
