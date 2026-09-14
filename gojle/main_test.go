package main

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func filetimeOf(t time.Time) uint64 {
	const ticksPerSecond = 10_000_000
	const epochGap = 11644473600
	return uint64((t.Unix()+epochGap)*ticksPerSecond + int64(t.Nanosecond())/100)
}

func putUTF16(b []byte, s string) {
	for i, c := range utf16.Encode([]rune(s)) {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
}

// makeV3Entry builds one DestList v3 entry byte-exact to the documented layout,
// so parseDestList's offsets are pinned by a round-trip.
func makeV3Entry(entryNum uint32, host string, mac []byte, lastMod time.Time, pin int32, access uint32, path string) []byte {
	e := make([]byte, 130+len([]rune(path))*2)
	// 0x08 VolumeDroid: GUID 11111111-2222-3333-4455-66778899AABB (LE first 3 groups)
	binary.LittleEndian.PutUint32(e[8:], 0x11111111)
	binary.LittleEndian.PutUint16(e[12:], 0x2222)
	binary.LittleEndian.PutUint16(e[14:], 0x3333)
	e[16], e[17] = 0x44, 0x55
	copy(e[18:24], []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB})
	// 0x18 FileDroid: node (last 6 bytes, 0x22..0x27) carries the MAC
	copy(e[24+10:24+16], mac)
	// 0x48 Hostname (16 bytes, NUL padded)
	copy(e[72:88], []byte(host))
	// 0x58 EntryNumber
	binary.LittleEndian.PutUint32(e[88:], entryNum)
	// 0x64 LastModified FILETIME
	binary.LittleEndian.PutUint64(e[100:], filetimeOf(lastMod))
	// 0x6C PinStatus
	binary.LittleEndian.PutUint32(e[108:], uint32(pin))
	// 0x74 AccessCount
	binary.LittleEndian.PutUint32(e[116:], access)
	// 0x80 path length (chars) + path
	binary.LittleEndian.PutUint16(e[128:], uint16(len([]rune(path))))
	putUTF16(e[130:], path)
	return e
}

func TestParseDestListV3(t *testing.T) {
	when := time.Date(2025, 3, 19, 7, 20, 55, 533000000, time.UTC)
	mac := []byte{0x00, 0x0C, 0x29, 0x91, 0x68, 0x96}
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], 3) // version 3
	binary.LittleEndian.PutUint32(hdr[4:], 1) // one entry
	entry := makeV3Entry(2, "DESKTOP-TEST", mac, when, -1 /*not pinned*/, 7, `C:\Users\jo\survey.zip`)
	got, err := parseDestList(append(hdr, entry...))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	e := got[0]
	if e.Path != `C:\Users\jo\survey.zip` {
		t.Errorf("Path = %q", e.Path)
	}
	if e.EntryNumber != 2 {
		t.Errorf("EntryNumber = %d, want 2", e.EntryNumber)
	}
	if e.Hostname != "DESKTOP-TEST" {
		t.Errorf("Hostname = %q", e.Hostname)
	}
	if e.LastModified != "/Date(1742368855533)/" {
		t.Errorf("LastModified = %q", e.LastModified)
	}
	if e.Pinned {
		t.Errorf("Pinned should be false for pin status -1")
	}
	if e.InteractionCount != uint32(7) {
		t.Errorf("InteractionCount = %v, want 7", e.InteractionCount)
	}
	if e.MacAddress != "00:0C:29:91:68:96" {
		t.Errorf("MacAddress = %q", e.MacAddress)
	}
	if e.VolumeDroid != "11111111-2222-3333-4455-66778899AABB" {
		t.Errorf("VolumeDroid = %q", e.VolumeDroid)
	}
	if e.MRUPosition != 0 {
		t.Errorf("MRUPosition = %d, want 0", e.MRUPosition)
	}
}

func TestParseDestListPinnedFlag(t *testing.T) {
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], 3)
	binary.LittleEndian.PutUint32(hdr[4:], 1)
	entry := makeV3Entry(1, "H", []byte{1, 2, 3, 4, 5, 6}, time.Now(), 0 /*pinned index 0*/, 1, `X`)
	got, _ := parseDestList(append(hdr, entry...))
	if len(got) != 1 || !got[0].Pinned {
		t.Fatalf("pin status 0 should mean Pinned=true, got %+v", got)
	}
}

func TestMacFromFileDroidZeroIsEmpty(t *testing.T) {
	if got := macFromFileDroid(make([]byte, 16)); got != "" {
		t.Errorf("all-zero droid should yield empty MAC, got %q", got)
	}
}

func TestDotnetDateZero(t *testing.T) {
	if got := dotnetDate(time.Time{}); got != "" {
		t.Errorf("zero time should render empty, got %q", got)
	}
}

func TestFiletimeRoundTrip(t *testing.T) {
	when := time.Date(2025, 3, 19, 7, 20, 55, 533000000, time.UTC)
	if got := filetimeToTime(filetimeOf(when)); !got.Equal(when) {
		t.Errorf("filetime round-trip = %v, want %v", got, when)
	}
}
