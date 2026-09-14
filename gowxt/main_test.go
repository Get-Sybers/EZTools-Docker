package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestExecFromAppId(t *testing.T) {
	appid := `[{"application":"c:\\a\\x.exe","platform":"windows_win32"},{"application":"X","platform":"afs"}]`
	if got := execFromAppId(appid); got != `c:\a\x.exe` {
		t.Errorf("execFromAppId = %q", got)
	}
	if got := execFromAppId(""); got != "" {
		t.Errorf("empty AppId = %q", got)
	}
	if got := execFromAppId("plain.exe"); got != "plain.exe" { // non-JSON passes through
		t.Errorf("plain = %q", got)
	}
}

func TestFromPayload(t *testing.T) {
	d, c := fromPayload(`{"displayText":"Report.docx","description":"downloaded"}`)
	if d != "Report.docx" || c != "downloaded" {
		t.Errorf("fromPayload = %q,%q", d, c)
	}
	if d, c := fromPayload(""); d != "" || c != "" {
		t.Errorf("empty payload = %q,%q", d, c)
	}
}

func TestUnixTS(t *testing.T) {
	if got := unixTS(int64(0)); got != "" {
		t.Errorf("zero = %q", got)
	}
	when := time.Date(2024, 1, 19, 5, 34, 13, 0, time.UTC)
	if got := unixTS(when.Unix()); got != "2024-01-19T05:34:13Z" {
		t.Errorf("unix = %q", got)
	}
	// a FILETIME (100-ns since 1601) is recognised and converted, not mis-dated
	ft := (when.Unix() + 11644473600) * 10_000_000
	if got := unixTS(ft); got != "2024-01-19T05:34:13Z" {
		t.Errorf("filetime = %q", got)
	}
}

func TestDurationOf(t *testing.T) {
	if got := durationOf(int64(100), int64(280)); got != "00:03:00" {
		t.Errorf("duration = %q", got)
	}
	if got := durationOf(int64(0), int64(280)); got != "" {
		t.Errorf("zero start = %q", got)
	}
}

func TestLooksLikeSQLite(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "ActivitiesCache.db")
	if err := os.WriteFile(good, append([]byte("SQLite format 3\x00"), make([]byte, 100)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if !looksLikeSQLite(good) {
		t.Error("SQLite-magic file not detected")
	}
	bad := filepath.Join(dir, "notes.txt")
	os.WriteFile(bad, []byte("nope"), 0o644)
	if looksLikeSQLite(bad) {
		t.Error("non-sqlite wrongly detected")
	}
}

// TestParseDBEndToEnd builds a real ActivitiesCache.db (modernc sqlite) and
// parses it through parseDB — end-to-end coverage of the Activity read + mapping.
func TestParseDBEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ActivitiesCache.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE Activity(Id BLOB, AppId TEXT, ActivityType INTEGER,
		LastModifiedTime INTEGER, ExpirationTime INTEGER, Payload BLOB, IsLocalOnly INTEGER,
		PlatformDeviceId TEXT, StartTime INTEGER, EndTime INTEGER, ClipboardPayload BLOB, ETag INTEGER)`)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2024, 1, 19, 5, 34, 13, 0, time.UTC).Unix()
	appid := `[{"application":"c:\\chrome.exe","platform":"windows_win32"}]`
	payload := `{"displayText":"Report.docx","description":"dl"}`
	_, err = db.Exec(`INSERT INTO Activity VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		[]byte("0123456789abcdef"), appid, int64(5), start+300, int64(0), payload, int64(1),
		"dev", start, start+180, nil, int64(42))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	var got []*record
	n, err := parseDB(dbPath, filepath.Join(dir, "work"), func(r *record) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatalf("parseDB: %v", err)
	}
	if n != 1 || len(got) != 1 {
		t.Fatalf("parsed %d rows, want 1", n)
	}
	r := got[0]
	if r.Executable != `c:\chrome.exe` {
		t.Errorf("Executable = %q", r.Executable)
	}
	if r.DisplayText != "Report.docx" || r.ContentInfo != "dl" {
		t.Errorf("payload fields = %q,%q", r.DisplayText, r.ContentInfo)
	}
	if r.StartTime != "2024-01-19T05:34:13Z" || r.Duration != "00:03:00" {
		t.Errorf("time = %q dur=%q", r.StartTime, r.Duration)
	}
	if r.ActivityType != 5 || r.ETag != 42 {
		t.Errorf("ints: type=%d etag=%d", r.ActivityType, r.ETag)
	}
	// the record round-trips to JSON with a stable field set
	if _, err := json.Marshal(r); err != nil {
		t.Errorf("json: %v", err)
	}
}
