package main

import "testing"

func TestHiveTypeOf(t *testing.T) {
	cases := map[string]string{
		"/x/NTUSER.DAT":   "NtUser",
		"/x/ntuser.dat":   "NtUser",
		"/x/UsrClass.dat": "UsrClass",
		"/x/SYSTEM":       "System",
		"/x/SOFTWARE":     "Software",
		"/x/SAM":          "Sam",
		"/x/SECURITY":     "Security",
		"/x/Amcache.hve":  "Amcache",
		"/x/random.bin":   "", // unknown -> empty, never a bogus token
	}
	for in, want := range cases {
		if got := hiveTypeOf(in); got != want {
			t.Errorf("hiveTypeOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLogFile(t *testing.T) {
	for _, p := range []string{"/x/NTUSER.DAT.LOG1", "/x/system.LOG2", "/x/SOFTWARE.LOG"} {
		if !isLogFile(p) {
			t.Errorf("isLogFile(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/x/NTUSER.DAT", "/x/SYSTEM", "/x/log.dat"} {
		if isLogFile(p) {
			t.Errorf("isLogFile(%q) = true, want false", p)
		}
	}
}

func TestCsvRowMatchesHeaderLen(t *testing.T) {
	r := &record{}
	if len(r.csvRow()) != len(csvHeader) {
		t.Errorf("csvRow has %d cols, header has %d", len(r.csvRow()), len(csvHeader))
	}
}
