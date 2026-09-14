// gowxt — Linux-native Windows Timeline (ActivitiesCache.db) parser for the
// DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's WxTCmd: it reads the Windows
// Timeline SQLite database (ActivitiesCache.db) with modernc.org/sqlite (pure
// Go, no cgo) and emits one record per row of the Activity table — the same
// facts WxTCmd surfaces (the executable from AppId, the display text /
// content info from Payload, the StartTime/EndTime/LastModified/Expiration
// timestamps, activity type) — as CSV or JSONL. It runs on Linux with no .NET,
// no shell and no libc (see Dockerfile: FROM scratch, uid 2000).
//
// SQLite needs a writable working area (journal/WAL/temp), but the pipeline
// mounts the input read-only under a read-only rootfs. gowxt copies the DB (and
// any -wal/-shm sidecars) into --work-dir (a writable tmpfs) and opens the copy,
// falling back to an immutable read-only open when the work dir is not writable.
//
// Scope: the Activity table (the timeline's core). Columns WxTCmd derives from
// providers other than the DB itself, or that this schema does not carry, are
// omitted rather than faked. Timestamps in ActivitiesCache.db are Unix epoch
// seconds; they are rendered RFC3339 UTC (empty when zero).
//
// Exit codes: 0 = parsed; 1 = usage or fatal error; 2 = at least one DB failed.
package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/hex"
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

	_ "modernc.org/sqlite"
)

type record struct {
	SourceFile       string `json:"SourceFile"`
	Id               string `json:"Id"`
	Executable       string `json:"Executable"`
	DisplayText      string `json:"DisplayText"`
	ContentInfo      string `json:"ContentInfo"`
	ActivityType     int64  `json:"ActivityType"`
	StartTime        string `json:"StartTime"`
	EndTime          string `json:"EndTime"`
	Duration         string `json:"Duration"`
	LastModified     string `json:"LastModifiedTime"`
	ExpirationTime   string `json:"ExpirationTime"`
	IsLocalOnly      int64  `json:"IsLocalOnly"`
	PlatformDevice   string `json:"PlatformDeviceId"`
	PackageIdHash    string `json:"PackageIdHash"`
	ETag             int64  `json:"ETag"`
	Payload          string `json:"Payload"`
	ClipboardPayload string `json:"ClipboardPayload"`
}

var csvHeader = []string{
	"SourceFile", "Id", "Executable", "DisplayText", "ContentInfo", "ActivityType",
	"StartTime", "EndTime", "Duration", "LastModifiedTime", "ExpirationTime",
	"IsLocalOnly", "PlatformDeviceId", "PackageIdHash", "ETag", "Payload", "ClipboardPayload",
}

func (r *record) csvRow() []string {
	return []string{
		r.SourceFile, r.Id, r.Executable, r.DisplayText, r.ContentInfo,
		strconv.FormatInt(r.ActivityType, 10), r.StartTime, r.EndTime, r.Duration,
		r.LastModified, r.ExpirationTime, strconv.FormatInt(r.IsLocalOnly, 10),
		r.PlatformDevice, r.PackageIdHash, strconv.FormatInt(r.ETag, 10),
		r.Payload, r.ClipboardPayload,
	}
}

// unixTS renders an ActivitiesCache Unix-epoch-seconds value as RFC3339 UTC, or
// "" when zero/absent. A plausibly-FILETIME value (100-ns since 1601, ~1.1e17
// for a modern date) is converted too, so a mixed source is not mis-dated.
func unixTS(v interface{}) string {
	n, ok := asInt(v)
	if !ok || n == 0 {
		return ""
	}
	if n > 100_000_000_000_000 { // looks like a FILETIME, not Unix seconds
		return time.Unix(n/10_000_000-11644473600, 0).UTC().Format(time.RFC3339)
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

func asInt(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case []byte:
		n, err := strconv.ParseInt(strings.TrimSpace(string(t)), 10, 64)
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func asString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprint(t)
	}
}

// guid renders the Id column: a 16-byte blob is a GUID, otherwise the value as
// text (schemas vary; never guess a shape that isn't there).
func guid(v interface{}) string {
	b, ok := v.([]byte)
	if !ok || len(b) != 16 {
		return asString(v)
	}
	// ActivitiesCache stores the GUID big-endian as text bytes in most builds;
	// present it as canonical hex groups from the raw bytes.
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}

// execFromAppId pulls the windows_win32 application path out of the AppId JSON
// array ([{"application","platform"}...]); falls back to the first entry.
func execFromAppId(appid string) string {
	appid = strings.TrimSpace(appid)
	if appid == "" || appid[0] != '[' {
		return appid
	}
	var entries []struct {
		Application string `json:"application"`
		Platform    string `json:"platform"`
	}
	if json.Unmarshal([]byte(appid), &entries) != nil || len(entries) == 0 {
		return appid
	}
	for _, e := range entries {
		if e.Platform == "windows_win32" && e.Application != "" {
			return e.Application
		}
	}
	return entries[0].Application
}

// fromPayload extracts (displayText, contentInfo) out of the Payload JSON.
func fromPayload(payload string) (string, string) {
	payload = strings.TrimSpace(payload)
	if payload == "" || payload[0] != '{' {
		return "", ""
	}
	var p map[string]interface{}
	if json.Unmarshal([]byte(payload), &p) != nil {
		return "", ""
	}
	display := firstStr(p, "displayText", "appDisplayName")
	content := firstStr(p, "description", "contentUri", "contentType")
	return display, content
}

func firstStr(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func durationOf(start, end interface{}) string {
	s, ok1 := asInt(start)
	e, ok2 := asInt(end)
	if !ok1 || !ok2 || s == 0 || e == 0 || e < s {
		return ""
	}
	d := time.Duration(e-s) * time.Second
	total := int64(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}

// openActivitiesDB opens the ActivitiesCache DB. Because the rootfs and input
// are read-only but SQLite wants a writable working area, it copies the DB (and
// any -wal/-shm sidecars) into workDir and opens the copy; if workDir is not
// writable it falls back to an immutable read-only open (which cannot see an
// un-checkpointed -wal, noted on stderr). Returns the DB and a cleanup func.
func openActivitiesDB(path, workDir string) (*sql.DB, func(), error) {
	cleanup := func() {}
	dsn := ""
	if copied, err := copyForWork(path, workDir); err == nil {
		dsn = "file:" + copied
		cleanup = func() {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				os.Remove(copied + suffix)
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "gowxt: work dir %s not usable (%v); opening %s read-only immutable "+
			"(an un-checkpointed -wal is not seen)\n", workDir, err, filepath.Base(path))
		dsn = "file:" + path + "?mode=ro&immutable=1"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		cleanup()
		return nil, func() {}, err
	}
	return db, func() { db.Close(); cleanup() }, nil
}

func copyForWork(path, workDir string) (string, error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(workDir, filepath.Base(path))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := copyFile(path+suffix, dst+suffix); err != nil && suffix == "" {
			return "", err // the main DB must copy; sidecars are best-effort
		}
	}
	return dst, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// parseDB reads the Activity table and streams a record per row. SELECT * and a
// by-name column map keeps it robust to Windows-version schema drift.
func parseDB(path, workDir string, emit func(*record) error) (int, error) {
	db, done, err := openActivitiesDB(path, workDir)
	if err != nil {
		return 0, err
	}
	defer done()

	rows, err := db.Query("SELECT * FROM Activity")
	if err != nil {
		return 0, fmt.Errorf("no Activity table: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	src := filepath.Base(path)
	n := 0
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		m := make(map[string]interface{}, len(cols))
		for i, c := range cols {
			m[c] = vals[i]
		}
		payload := asString(m["Payload"])
		display, content := fromPayload(payload)
		atype, _ := asInt(m["ActivityType"])
		local, _ := asInt(m["IsLocalOnly"])
		etag, _ := asInt(m["ETag"])
		rec := &record{
			SourceFile:       src,
			Id:               guid(m["Id"]),
			Executable:       execFromAppId(asString(m["AppId"])),
			DisplayText:      display,
			ContentInfo:      content,
			ActivityType:     atype,
			StartTime:        unixTS(m["StartTime"]),
			EndTime:          unixTS(m["EndTime"]),
			Duration:         durationOf(m["StartTime"], m["EndTime"]),
			LastModified:     unixTS(m["LastModifiedTime"]),
			ExpirationTime:   unixTS(m["ExpirationTime"]),
			IsLocalOnly:      local,
			PlatformDevice:   asString(m["PlatformDeviceId"]),
			PackageIdHash:    asString(m["PackageIdHash"]),
			ETag:             etag,
			Payload:          payload,
			ClipboardPayload: asString(m["ClipboardPayload"]),
		}
		if err := emit(rec); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

const sqliteMagic = "SQLite format 3\x00"

func looksLikeSQLite(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [16]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == sqliteMagic
}

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
			fmt.Fprintf(os.Stderr, "gowxt: skipping unreadable %s: %v\n", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
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
		file    = flag.String("f", "", "single ActivitiesCache.db to parse")
		dir     = flag.String("d", "", "directory to scan recursively for ActivitiesCache.db")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: Activity_WxTCmd_Output.jsonl)")
		csvDir  = flag.String("csv", "", "directory to write CSV output to instead of JSONL")
		csvF    = flag.String("csvf", "", "CSV file name (default: Activity_WxTCmd_Output.csv)")
		workDir = flag.String("work-dir", os.TempDir(), "writable dir for the SQLite working copy")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "gowxt: exactly one of -f <db> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}

	dirMode := *dir != ""
	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gowxt: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "gowxt: no files found")
		os.Exit(1)
	}

	var w io.WriteCloser
	var cw *csv.Writer
	var enc *json.Encoder
	if *csvDir != "" {
		w, err = openOut(*csvDir, *csvF, "Activity_WxTCmd_Output.csv")
	} else {
		w, err = openOut(*jsonDir, *jsonF, "Activity_WxTCmd_Output.jsonl")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gowxt: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if w != os.Stdout {
			w.Close()
		}
	}()
	if *csvDir != "" {
		cw = csv.NewWriter(w)
		if err := cw.Write(csvHeader); err != nil {
			fmt.Fprintf(os.Stderr, "gowxt: write: %v\n", err)
			os.Exit(1)
		}
	} else {
		enc = json.NewEncoder(w)
	}
	emit := func(r *record) error {
		if cw != nil {
			return cw.Write(r.csvRow())
		}
		return enc.Encode(r)
	}

	failed, parsed, activities := 0, 0, 0
	for _, p := range inputs {
		if dirMode && !looksLikeSQLite(p) {
			continue // -d: pick the SQLite DB(s) out of the tree by header
		}
		n, err := parseDB(p, *workDir, emit)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "gowxt: FAILED %s: %v\n", p, err)
			continue
		}
		parsed++
		activities += n
		if !*quiet {
			fmt.Fprintf(os.Stderr, "gowxt: parsed %s (%d activities)\n", p, n)
		}
	}
	if cw != nil {
		cw.Flush()
		if err := cw.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "gowxt: write: %v\n", err)
			os.Exit(1)
		}
	}
	if dirMode && parsed == 0 && failed == 0 {
		fmt.Fprintf(os.Stderr, "gowxt: no ActivitiesCache.db found under %s\n", *dir)
		os.Exit(1)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "gowxt: %d activities across %d database(s)\n", activities, parsed)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "gowxt: %d database(s) failed\n", failed)
		os.Exit(2)
	}
}
