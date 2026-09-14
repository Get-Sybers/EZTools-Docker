package main

import (
	"testing"

	"www.velocidex.com/golang/regparser"
)

func TestValueDataString(t *testing.T) {
	cases := []struct {
		name string
		vd   *regparser.ValueData
		want string
	}{
		{"nil", nil, ""},
		{"dword-zero", &regparser.ValueData{Type: regparser.REG_DWORD, Uint64: 0}, "0"},
		{"dword-nonzero", &regparser.ValueData{Type: regparser.REG_DWORD, Uint64: 42}, "42"},
		{"qword-zero", &regparser.ValueData{Type: regparser.REG_QWORD, Uint64: 0}, "0"},
		{"sz", &regparser.ValueData{Type: regparser.REG_SZ, String: "hello"}, "hello"},
		{"multi-sz", &regparser.ValueData{Type: regparser.REG_MULTI_SZ, MultiSz: []string{"a", "b"}}, "a b"},
		{"binary", &regparser.ValueData{Type: regparser.REG_BINARY, Data: []byte{0xde, 0xad}}, "dead"},
		// A REG_BINARY value whose bytes happen to be all-zero still renders as
		// hex, not the integer path (regression guard for the type-keyed switch).
		{"binary-zero", &regparser.ValueData{Type: regparser.REG_BINARY, Data: []byte{0x00, 0x00}}, "0000"},
	}
	for _, c := range cases {
		if got := valueDataString(c.vd); got != c.want {
			t.Errorf("valueDataString(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}

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
