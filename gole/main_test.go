package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	lnk "github.com/parsiya/golnk"
)

func TestTsZeroIsEmpty(t *testing.T) {
	if got := ts(time.Time{}); got != "" {
		t.Fatalf("zero time should render empty, got %q", got)
	}
}

func TestTsRendersUTCRFC3339Nano(t *testing.T) {
	in := time.Date(2025, 3, 18, 5, 39, 30, 673307900, time.FixedZone("x", 3600))
	got := ts(in)
	want := "2025-03-18T04:39:30.6733079Z" // normalised to UTC
	if got != want {
		t.Fatalf("ts() = %q, want %q", got, want)
	}
}

func TestSetFlagsSortedAndSetOnly(t *testing.T) {
	fm := lnk.FlagMap{"HasLinkInfo": true, "IsUnicode": true, "HasArguments": false}
	got := setFlags(fm)
	want := "HasLinkInfo, IsUnicode" // sorted, unset dropped
	if got != want {
		t.Fatalf("setFlags() = %q, want %q", got, want)
	}
}

func TestSetFlagsEmpty(t *testing.T) {
	if got := setFlags(lnk.FlagMap{"A": false}); got != "" {
		t.Fatalf("no set flags should render empty, got %q", got)
	}
}

func TestCsvHeaderMatchesRowWidth(t *testing.T) {
	r := &record{}
	if len(r.csvRow()) != len(csvHeader) {
		t.Fatalf("csvRow width %d != header width %d", len(r.csvRow()), len(csvHeader))
	}
}

func TestLooksLikeLnkMagic(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "a.lnk")
	if err := os.WriteFile(good, []byte(lnkMagic+"rest"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(bad, []byte("NOPEnope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !looksLikeLnk(good) {
		t.Errorf("expected magic file to be detected as .lnk")
	}
	if looksLikeLnk(bad) {
		t.Errorf("non-magic file must not be detected as .lnk")
	}
	if looksLikeLnk(filepath.Join(dir, "missing")) {
		t.Errorf("missing file must not be detected as .lnk")
	}
}
