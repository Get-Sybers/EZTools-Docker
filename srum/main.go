// ese_dump — Linux-native ESE database dumper (SRUM / SUM) for the DX_DFIR
// pipeline.
//
// SrumECmd and SumECmd cannot run on non-Windows hosts: both read ESE
// databases through Microsoft.Database.ManagedEsent, a P/Invoke wrapper over
// Windows' native esent.dll ("Non-Windows platforms not supported due to the
// need to load ESI specific Windows libraries!"). This tool uses
// Velociraptor's go-ese, a pure-Go ESE implementation, so SRUDB.dat and SUM
// databases (Current.mdb / SystemIdentity.mdb) parse on Linux.
//
// Two run modes:
//
//	-f <db>    one database: an extracted SRUDB.dat / Current.mdb / any ESE file
//	-d <root>  a mounted disk image root (or any staged tree): finds every
//	           SRUM database (SRUDB.dat) and SUM database (*.mdb directly
//	           under a SUM/ directory) case-insensitively, and dumps each
//	           into its own sub-directory; rows gain a SourceDb field.
//
// Output is one JSONL (or CSV) file per table. For SRUM databases the
// SruDbIdMapTable is decoded automatically: AppId/UserId columns in the data
// tables gain AppIdName / UserIdName fields (UTF-16LE strings, or the SID for
// IdType 3 entries), which is the useful part of SrumECmd's enrichment.
// Well-known SRUM provider GUID tables are given friendly file names; the raw
// table name is always kept in the rows. ESE DateTime columns arrive as
// RFC3339 strings (go-ese converts them); raw integer FILETIME columns are
// left as-is.
//
// Exit codes: 0 = all requested tables dumped; 1 = usage or fatal error;
// 2 = at least one table or database failed (the rest still written,
// failures on stderr).
package main

import (
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
	"strings"
	"unicode/utf16"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/go-ese/parser"
)

// Friendly names for well-known SRUM provider tables. The raw GUID stays in
// the output rows; aliases only make file names and -t selection readable.
// {973F5D5C…}, {D10CA2FE…FA89}, {DD6636C4…} match plaso's srum plugin; the
// rest are the standard SRUM provider set documented across DFIR references.
var srumAliases = map[string]string{
	"{973F5D5C-1D90-4944-BE8E-24B94231A174}":   "NetworkDataUsage",
	"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}":   "ApplicationResourceUsage",
	"{DD6636C4-8929-4683-974E-22C046A43763}":   "NetworkConnectivityUsage",
	"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}":   "EnergyUsage",
	"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": "EnergyUsageLT",
	"{5C8CF1C7-7257-4F13-B223-970EF5939312}":   "AppTimelineProvider",
	"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}":   "PushNotifications",
}

func aliasFor(table string) string {
	if a, ok := srumAliases[table]; ok {
		return a
	}
	return ""
}

// safeName returns a filesystem-friendly name for a table's output file.
func safeName(table string) string {
	if a := aliasFor(table); a != "" {
		return a
	}
	r := strings.NewReplacer("{", "", "}", "", "/", "_", "\\", "_", " ", "_")
	return r.Replace(table)
}

type idEntry struct {
	idType int64
	name   string
}

// decodeIdBlob turns SruDbIdMapTable IdBlob hex into a usable string:
// UTF-16LE text for IdType 0/1/2, a decoded SID for IdType 3.
func decodeIdBlob(idType int64, blobHex string) string {
	raw, err := hex.DecodeString(blobHex)
	if err != nil || len(raw) == 0 {
		return ""
	}
	if idType == 3 {
		return decodeSid(raw)
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// decodeSid renders a binary Windows SID as S-1-… (revision, 48-bit
// big-endian authority, little-endian 32-bit sub-authorities).
func decodeSid(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	rev, n := b[0], int(b[1])
	if len(b) < 8+4*n {
		return ""
	}
	auth := uint64(0)
	for _, x := range b[2:8] {
		auth = auth<<8 | uint64(x)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", rev, auth)
	for i := 0; i < n; i++ {
		o := 8 + 4*i
		sub := uint32(b[o]) | uint32(b[o+1])<<8 | uint32(b[o+2])<<16 | uint32(b[o+3])<<24
		fmt.Fprintf(&sb, "-%d", sub)
	}
	return sb.String()
}

func asInt64(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int32:
		return int64(x), true
	case int16:
		return int64(x), true
	case int8:
		return int64(x), true
	case int:
		return int64(x), true
	case uint64:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint8:
		return int64(x), true
	case float64:
		return int64(x), true
	}
	return 0, false
}

// loadIdMap reads SruDbIdMapTable into IdIndex -> decoded entry, if present.
func loadIdMap(cat *parser.Catalog) map[int64]idEntry {
	if _, ok := cat.Tables.Get("SruDbIdMapTable"); !ok {
		return nil
	}
	m := make(map[int64]idEntry)
	err := cat.DumpTable("SruDbIdMapTable", func(row *ordereddict.Dict) error {
		idx, ok1 := row.Get("IdIndex")
		typ, ok2 := row.Get("IdType")
		if !ok1 || !ok2 {
			return nil
		}
		i, ok1 := asInt64(idx)
		t, ok2 := asInt64(typ)
		if !ok1 || !ok2 {
			return nil
		}
		name := ""
		if blob, ok := row.Get("IdBlob"); ok {
			if s, ok := blob.(string); ok {
				name = decodeIdBlob(t, s)
			}
		}
		m[i] = idEntry{idType: t, name: name}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ese_dump: SruDbIdMapTable read failed, continuing without enrichment: %v\n", err)
		return nil
	}
	return m
}

func tableColumns(cat *parser.Catalog, name string) []string {
	t, ok := cat.Tables.Get(name)
	if !ok {
		return nil
	}
	table, ok := t.(*parser.Table)
	if !ok {
		return nil
	}
	var cols []string
	for _, c := range table.Columns {
		cols = append(cols, c.Name)
	}
	return cols
}

func openOut(dir, name string) (io.WriteCloser, error) {
	if dir == "" {
		return os.Stdout, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return os.Create(filepath.Join(dir, name))
}

func dumpTable(cat *parser.Catalog, table string, idMap map[int64]idEntry,
	jsonDir, csvDir, sourceDb string) (int, error) {
	enrich := func(row *ordereddict.Dict) {
		if idMap == nil {
			return
		}
		for _, col := range []struct{ src, dst string }{
			{"AppId", "AppIdName"}, {"UserId", "UserIdName"},
		} {
			if v, ok := row.Get(col.src); ok {
				if i, ok := asInt64(v); ok {
					if e, ok := idMap[i]; ok && e.name != "" {
						row.Set(col.dst, e.name)
					}
				}
			}
		}
	}

	name := safeName(table)
	rows := 0

	if csvDir != "" {
		w, err := openOut(csvDir, name+".csv")
		if err != nil {
			return 0, err
		}
		defer func() {
			if w != os.Stdout {
				w.Close()
			}
		}()
		cw := csv.NewWriter(w)
		var header []string
		if sourceDb != "" {
			header = append(header, "SourceDb")
		}
		header = append(header, tableColumns(cat, table)...)
		if idMap != nil {
			for _, extra := range []string{"AppIdName", "UserIdName"} {
				for _, h := range header {
					if h == strings.TrimSuffix(extra, "Name") {
						header = append(header, extra)
						break
					}
				}
			}
		}
		if err := cw.Write(header); err != nil {
			return 0, err
		}
		err = cat.DumpTable(table, func(row *ordereddict.Dict) error {
			rows++
			enrich(row)
			out := make([]string, len(header))
			for i, h := range header {
				if h == "SourceDb" && sourceDb != "" {
					out[i] = sourceDb
					continue
				}
				if v, ok := row.Get(h); ok && v != nil {
					out[i] = fmt.Sprintf("%v", v)
				}
			}
			return cw.Write(out)
		})
		cw.Flush()
		if err == nil {
			err = cw.Error()
		}
		return rows, err
	}

	w, err := openOut(jsonDir, name+".jsonl")
	if err != nil {
		return 0, err
	}
	defer func() {
		if w != os.Stdout {
			w.Close()
		}
	}()
	enc := json.NewEncoder(w)
	err = cat.DumpTable(table, func(row *ordereddict.Dict) error {
		rows++
		enrich(row)
		out := ordereddict.NewDict()
		if sourceDb != "" {
			out.Set("SourceDb", sourceDb)
		}
		out.Set("Table", table)
		if a := aliasFor(table); a != "" {
			out.Set("TableAlias", a)
		}
		out.MergeFrom(row)
		return enc.Encode(out)
	})
	return rows, err
}

type dbHit struct {
	path string
	kind string // "SRUM" or "SUM" — logging only, parsing is identical
}

// findDatabases walks a mounted image root (or any staged tree) and returns
// every SRUM database (SRUDB.dat) and SUM database (*.mdb whose immediate
// parent directory is SUM/), matched case-insensitively. Unreadable
// subtrees are skipped with a note, not fatal — disk image mounts routinely
// contain them. A root that cannot be read at all IS an error: reporting
// "no databases found" for a missing mount would mislead.
func findDatabases(root string) ([]dbHit, error) {
	var hits []dbHit
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			fmt.Fprintf(os.Stderr, "ese_dump: skipping unreadable %s: %v\n", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		switch {
		case name == "srudb.dat":
			hits = append(hits, dbHit{p, "SRUM"})
		case strings.HasSuffix(name, ".mdb") &&
			strings.EqualFold(filepath.Base(filepath.Dir(p)), "sum"):
			hits = append(hits, dbHit{p, "SUM"})
		}
		return nil
	})
	sort.Slice(hits, func(i, j int) bool { return hits[i].path < hits[j].path })
	return hits, err
}

// dbSubdir builds a stable per-database output directory name like
// SRUM_SRUDB or SUM_Current, de-duplicated when an image holds several.
func dbSubdir(hit dbHit, used map[string]int) string {
	base := strings.TrimSuffix(filepath.Base(hit.path), filepath.Ext(hit.path))
	name := hit.kind + "_" + safeName(base)
	used[name]++
	if used[name] > 1 {
		name = fmt.Sprintf("%s-%d", name, used[name])
	}
	return name
}

// processDb opens and dumps one database. strictTables makes an unknown -t
// entry fatal (single -f mode); in root-scan mode it is noted and skipped
// instead, since a SUM database has no SRUM tables and vice versa. Returns
// the number of failed tables plus any fatal open/catalog error.
func processDb(path, sourceDb, jsonDir, csvDir, tablesFlag string,
	list, strictTables, quiet bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	ctx, err := parser.NewESEContext(f)
	if err != nil {
		return 0, fmt.Errorf("not a readable ESE database: %w", err)
	}
	cat, err := parser.ReadCatalog(ctx)
	if err != nil {
		return 0, fmt.Errorf("catalog read failed: %w", err)
	}

	label := func(table string) string {
		if sourceDb != "" {
			return sourceDb + ": " + table
		}
		return table
	}

	if list {
		if sourceDb != "" {
			fmt.Println("== " + sourceDb)
		}
		for _, name := range cat.Tables.Keys() {
			line := name
			if a := aliasFor(name); a != "" {
				line += " (" + a + ")"
			}
			fmt.Println(line)
			fmt.Println("    " + strings.Join(tableColumns(cat, name), ", "))
		}
		return 0, nil
	}

	// Resolve the requested table set.
	var selected []string
	if tablesFlag == "" {
		for _, name := range cat.Tables.Keys() {
			if strings.HasPrefix(name, "MSys") {
				continue
			}
			selected = append(selected, name)
		}
	} else {
		byAlias := map[string]string{}
		for guid, alias := range srumAliases {
			byAlias[strings.ToLower(alias)] = guid
		}
		for _, want := range strings.Split(tablesFlag, ",") {
			want = strings.TrimSpace(want)
			if want == "" {
				continue
			}
			resolved := want
			if guid, ok := byAlias[strings.ToLower(want)]; ok {
				resolved = guid
			}
			found := ""
			for _, name := range cat.Tables.Keys() {
				if strings.EqualFold(name, resolved) {
					found = name
					break
				}
			}
			if found == "" {
				if strictTables {
					return 0, fmt.Errorf("table %q not found (use --list)", want)
				}
				fmt.Fprintf(os.Stderr, "ese_dump: %s: table %q not present, skipping\n", sourceDb, want)
				continue
			}
			selected = append(selected, found)
		}
	}

	idMap := loadIdMap(cat)
	if idMap != nil && !quiet {
		fmt.Fprintf(os.Stderr, "ese_dump: %s: SRUM id map loaded (%d entries) — AppIdName/UserIdName enrichment on\n",
			path, len(idMap))
	}

	failed := 0
	for _, table := range selected {
		rows, err := dumpTable(cat, table, idMap, jsonDir, csvDir, sourceDb)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "ese_dump: FAILED %s after %d rows: %v\n", label(table), rows, err)
			continue
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "ese_dump: dumped %s (%d rows)\n", label(table), rows)
		}
	}
	return failed, nil
}

func main() {
	var (
		file    = flag.String("f", "", "one ESE database to parse (SRUDB.dat, Current.mdb, ...)")
		root    = flag.String("d", "", "mounted disk image root (or staged tree) to scan for SRUM/SUM databases")
		tables  = flag.String("t", "", "comma-separated tables to dump (name, SRUM alias, or GUID); default: every non-MSys table")
		list    = flag.Bool("list", false, "list tables and columns, then exit")
		jsonDir = flag.String("json", "", "directory for per-table JSONL files (default: stdout stream)")
		csvDir  = flag.String("csv", "", "directory for per-table CSV files instead of JSONL")
		quiet   = flag.Bool("q", false, "suppress per-table progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*root == "") {
		fmt.Fprintln(os.Stderr, "ese_dump: exactly one of -f <database> or -d <root> is required")
		flag.Usage()
		os.Exit(1)
	}

	// Mode 2: one extracted database, output exactly as requested.
	if *file != "" {
		failed, err := processDb(*file, "", *jsonDir, *csvDir, *tables, *list, true, *quiet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ese_dump: %s: %v\n", *file, err)
			os.Exit(1)
		}
		if failed > 0 {
			fmt.Fprintf(os.Stderr, "ese_dump: %d tables failed\n", failed)
			os.Exit(2)
		}
		return
	}

	// Mode 1: a mounted disk image root — find every SRUM/SUM database and
	// dump each into its own sub-directory (SRUM_SRUDB/, SUM_Current/, ...).
	hits, err := findDatabases(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ese_dump: cannot scan %s: %v\n", *root, err)
		os.Exit(1)
	}
	if len(hits) == 0 {
		fmt.Fprintf(os.Stderr, "ese_dump: no SRUM or SUM databases found under %s\n", *root)
		os.Exit(1)
	}
	used := map[string]int{}
	failedDbs, failedTables := 0, 0
	for _, hit := range hits {
		rel, err := filepath.Rel(*root, hit.path)
		if err != nil {
			rel = hit.path
		}
		sub := dbSubdir(hit, used)
		jd, cd := *jsonDir, *csvDir
		if jd != "" {
			jd = filepath.Join(jd, sub)
		}
		if cd != "" {
			cd = filepath.Join(cd, sub)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "ese_dump: %s database %s -> %s\n", hit.kind, rel, sub)
		}
		ft, err := processDb(hit.path, rel, jd, cd, *tables, *list, false, *quiet)
		if err != nil {
			failedDbs++
			fmt.Fprintf(os.Stderr, "ese_dump: FAILED %s: %v\n", rel, err)
			continue
		}
		failedTables += ft
	}
	if failedDbs > 0 || failedTables > 0 {
		fmt.Fprintf(os.Stderr, "ese_dump: %d databases and %d tables failed\n", failedDbs, failedTables)
		os.Exit(2)
	}
}
