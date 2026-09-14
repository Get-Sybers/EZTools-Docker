// gosbe — Linux-native Windows ShellBags parser for the DX_DFIR pipeline.
//
// A static-Go substitute for Eric Zimmerman's SBECmd: it walks the BagMRU
// shellbag tree in NTUSER.DAT / UsrClass.dat with Velociraptor's regparser and
// emits one record per shellbag (the folder a user browsed in Explorer), with
// the reconstructed AbsolutePath. Runs on Linux with no .NET, no shell, no libc
// (Dockerfile: FROM scratch, uid 2000).
//
// Dirty-hive .LOG1/.LOG2 transaction logs ARE replayed (regparser.RecoverHive)
// unless --nl, matching SBECmd; the recovered copy is written under --work-dir
// (a writable tmpfs, the rootfs being read-only).
//
// SHELL-ITEM DECODING (never faked): gosbe decodes the common shell-item types —
// 0x1F root/GUID folders (mapped to known-folder names), 0x2F volumes (drive
// letters), and 0x30-0x3F file/directory entries (the ANSI short name, plus the
// BEEF0004 extension block's Unicode long name when present). Other item types
// (property/delegate 0x00, network 0x40-0x4F, URI 0x61, …) are emitted with
// their ShellType and hex value but NO reconstructed name — never an invented
// path. AbsolutePath is the join of the decoded names from the BagMRU root.
//
// Exit codes: 0 = ok; 1 = usage/fatal; 2 = at least one hive failed to parse.
package main

import (
	"encoding/binary"
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

	"www.velocidex.com/golang/regparser"
)

type record struct {
	HivePath      string `json:"HivePath"`
	BagPath       string `json:"BagPath"`  // the BagMRU registry key path
	Slot          int    `json:"Slot"`     // the numbered value index in the parent
	NodeSlot      int64  `json:"NodeSlot"` // links to Bags\<NodeSlot>
	MRUPosition   int    `json:"MRUPosition"`
	ShellType     string `json:"ShellType"` // hex of the shell-item type byte
	Value         string `json:"Value"`     // decoded item name ("" if not decoded)
	AbsolutePath  string `json:"AbsolutePath"`
	LastWriteTime string `json:"LastWriteTime"`
}

// knownFolders maps the common shell-item root GUIDs to a readable name.
var knownFolders = map[string]string{
	"20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
	"031e4825-7b94-4dc3-b131-e946b44c8dd5": "Users Libraries",
	"59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
	"b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
	"374de290-123f-4565-9164-39c4925e467b": "Downloads",
	"1cf1260c-4dd0-4ebb-811f-33c572699fde": "Music",
	"a0953c92-50dc-43bf-be83-3742fed03c9c": "Videos",
	"33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
	"f42ee2d3-909f-4907-8871-4c22fc0bf756": "Documents",
	"679f85cb-0220-4080-b29b-5540cc05aab6": "Home",
}

// decodeGUID reads a little-endian mixed-endian registry GUID at b[0:16].
func decodeGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]), b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func cstr(b []byte) string {
	if i := indexZero(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// beefLongName extracts the Unicode long name from a file-entry's BEEF0004
// extension block, or "" if it cannot be located cleanly.
//
// The long name is a null-terminated UTF-16LE string whose offset within the
// block is version-dependent (empirically verified against real Win8.1/10
// hives: version 9 places it at block+46, past the created/accessed DOS
// timestamps, the version-7 NTFS file reference, and the version-8 fields).
// A candidate is accepted only if it decodes to a clean filename (isCleanName),
// which rejects the misaligned high-codepoint junk a wrong offset yields; the
// caller falls back to the ANSI short name when this returns "".
func beefLongName(item []byte) string {
	sig := []byte{0x04, 0x00, 0xEF, 0xBE}
	idx := -1
	for i := 0; i+4 <= len(item); i++ {
		if item[i] == sig[0] && item[i+1] == sig[1] && item[i+2] == sig[2] && item[i+3] == sig[3] {
			idx = i
			break
		}
	}
	if idx < 4 {
		return ""
	}
	bs := idx - 4 // block start (signature is at block offset 4)
	if bs+4 > len(item) {
		return ""
	}
	ver := binary.LittleEndian.Uint16(item[bs+2 : bs+4])
	// version-based header size (offset from block start to the long name)
	var candidates []int
	switch {
	case ver >= 8:
		candidates = []int{bs + 46, bs + 38, bs + 18}
	case ver == 7:
		candidates = []int{bs + 38, bs + 18}
	case ver >= 3:
		candidates = []int{bs + 18}
	default:
		return ""
	}
	for _, off := range candidates {
		if off >= 0 && off < len(item) {
			if n := utf16FromLE(item[off:]); isCleanName(n) {
				return n
			}
		}
	}
	return ""
}

func utf16FromLE(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// isCleanName reports whether s is a plausible filename: 1..260 runes, every one
// a letter/digit/space or common filename punctuation. This cleanly rejects the
// random high-codepoint runes produced when a UTF-16 name is read at the wrong
// offset (a correctly aligned name is latin/ASCII-ish text).
func isCleanName(s string) bool {
	if len(s) < 1 || len([]rune(s)) > 260 {
		return false
	}
	const punct = " .-_()[]{}&'+,;=!@#$%^~`" + " "
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case strings.ContainsRune(punct, r):
		case r >= 0x00c0 && r <= 0x024f: // Latin-1/Extended letters (accented names)
		default:
			return false
		}
	}
	return true
}

// decodeShellItem returns (name, shellTypeHex). name is "" when the type is not
// decoded (never invented).
func decodeShellItem(item []byte) (string, string) {
	if len(item) < 3 {
		return "", ""
	}
	t := item[2]
	th := fmt.Sprintf("0x%02X", t)
	switch {
	case t == 0x1F: // root / GUID folder
		if len(item) >= 20 {
			g := decodeGUID(item[4:20])
			if name, ok := knownFolders[g]; ok {
				return name, th
			}
			return "{" + g + "}", th
		}
	case t == 0x2F: // volume (drive)
		if len(item) > 3 {
			return strings.TrimRight(cstr(item[3:]), "\x00"), th
		}
	case t >= 0x30 && t <= 0x3F: // file / directory entry
		if long := beefLongName(item); long != "" {
			return long, th
		}
		if len(item) > 14 { // ANSI primary (short) name at offset 14
			return cstr(item[14:]), th
		}
	}
	return "", th
}

func dwordValue(node *regparser.CM_KEY_NODE, name string) (int64, bool) {
	for _, v := range node.Values() {
		if strings.EqualFold(v.ValueName(), name) {
			vd := v.ValueData()
			if vd != nil {
				return int64(vd.Uint64), true
			}
		}
	}
	return 0, false
}

func mruOrder(node *regparser.CM_KEY_NODE) map[int]int {
	order := map[int]int{}
	for _, v := range node.Values() {
		if strings.EqualFold(v.ValueName(), "MRUListEx") {
			vd := v.ValueData()
			if vd == nil {
				break
			}
			b := vd.Data
			pos := 0
			for i := 0; i+4 <= len(b); i += 4 {
				slot := int(int32(binary.LittleEndian.Uint32(b[i : i+4])))
				if slot < 0 {
					break // 0xFFFFFFFF terminator
				}
				order[slot] = pos
				pos++
			}
		}
	}
	return order
}

func lastWrite(node *regparser.CM_KEY_NODE) string {
	if node == nil {
		return ""
	}
	ft := node.LastWriteTime()
	if ft == nil || ft.Time.IsZero() {
		return ""
	}
	return ft.Time.UTC().Format("2006-01-02 15:04:05.0000000")
}

// walkBag recurses a BagMRU node: each numbered value is a shell item; the
// same-numbered subkey is its child bag.
func walkBag(node *regparser.CM_KEY_NODE, keyPath, parentPath, hivePath string, e *emitter) (int, error) {
	if node == nil {
		return 0, nil
	}
	order := mruOrder(node)
	nodeSlot, _ := dwordValue(node, "NodeSlot")
	lw := lastWrite(node)
	// index the numbered shell-item values
	items := map[int][]byte{}
	for _, v := range node.Values() {
		name := v.ValueName()
		if isNumeric(name) {
			if vd := v.ValueData(); vd != nil && len(vd.Data) > 0 {
				items[atoiSafe(name)] = vd.Data
			}
		}
	}
	subByIdx := map[int]*regparser.CM_KEY_NODE{}
	for _, sk := range node.Subkeys() {
		if isNumeric(sk.Name()) {
			subByIdx[atoiSafe(sk.Name())] = sk
		}
	}
	slots := make([]int, 0, len(items))
	for i := range items {
		slots = append(slots, i)
	}
	sort.Ints(slots)
	n := 0
	for _, slot := range slots {
		name, th := decodeShellItem(items[slot])
		abs := parentPath
		if name != "" {
			if abs != "" {
				abs = strings.TrimRight(abs, "\\") + "\\" + name // avoid "C:\\Users"
			} else {
				abs = name
			}
		}
		mru := -1
		if p, ok := order[slot]; ok {
			mru = p
		}
		rec := &record{
			HivePath: hivePath, BagPath: keyPath, Slot: slot, NodeSlot: nodeSlot,
			MRUPosition: mru, ShellType: th, Value: name, AbsolutePath: abs,
			LastWriteTime: lw,
		}
		if err := e.emit(rec); err != nil {
			return n, err
		}
		n++
		if sub, ok := subByIdx[slot]; ok {
			sn, err := walkBag(sub, keyPath+"\\"+sub.Name(), abs, hivePath, e)
			if err != nil {
				return n, err
			}
			n += sn
		}
	}
	return n, nil
}

// bagRoots are the BagMRU roots to try per hive (NtUser vs UsrClass layouts).
var bagRoots = []string{
	`Software\Microsoft\Windows\Shell\BagMRU`,
	`Software\Microsoft\Windows\ShellNoRoam\BagMRU`,
	`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`,
	`Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU`,
}

func runHive(hivePath, workDir string, replay, quiet bool, e *emitter) (int, error) {
	reg, cleanup, note, replayFailed, err := openHive(hivePath, workDir, replay)
	if err != nil {
		return 0, err
	}
	defer cleanup()
	// A dirty-hive replay that fell back to the committed state is a fidelity
	// warning (recent shellbag transactions may be missing), so surface it even
	// under -q; a successful recovery is routine progress, shown only when not quiet.
	if replayFailed {
		fmt.Fprintf(os.Stderr, "gosbe: WARNING %s: %s\n", hivePath, note)
	} else if !quiet && note != "" && note != "committed" {
		fmt.Fprintf(os.Stderr, "gosbe: %s: %s\n", hivePath, note)
	}
	n := 0
	for _, root := range bagRoots {
		node := reg.OpenKey(root)
		if node == nil {
			continue
		}
		rn, err := walkBag(node, root, "", hivePath, e)
		if err != nil {
			return n, err
		}
		n += rn
	}
	return n, nil
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

type emitter struct{ enc *json.Encoder }

func (e *emitter) emit(r *record) error { return e.enc.Encode(r) }

const regfMagic = "regf"

func isLogFile(p string) bool {
	u := strings.ToUpper(p)
	return strings.HasSuffix(u, ".LOG") || strings.HasSuffix(u, ".LOG1") || strings.HasSuffix(u, ".LOG2")
}

func looksLikeHive(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == regfMagic
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
			fmt.Fprintf(os.Stderr, "gosbe: skipping unreadable %s: %v\n", p, err)
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

// openHive: replay .LOG1/.LOG2 into a recovered copy under workDir when replay
// is set and they exist, else parse the committed hive. Graceful fallback.
// The returned bool is set when a dirty-hive .LOG replay was attempted but
// failed and parsing fell back to the committed state (a fidelity warning).
func openHive(p, workDir string, replay bool) (*regparser.Registry, func(), string, bool, error) {
	hf, err := os.Open(p)
	if err != nil {
		return nil, nil, "", false, err
	}
	var logs []*os.File
	if replay {
		for _, suffix := range []string{".LOG1", ".LOG2"} {
			if lf, lerr := os.Open(p + suffix); lerr == nil {
				logs = append(logs, lf)
			}
		}
	}
	if len(logs) > 0 {
		old := os.Getenv("TMPDIR")
		_ = os.Setenv("TMPDIR", workDir)
		recovered, rerr := regparser.RecoverHive(hf, logs...)
		_ = os.Setenv("TMPDIR", old)
		for _, lf := range logs {
			lf.Close()
		}
		if rerr == nil {
			hf.Close()
			reg, nerr := regparser.NewRegistry(recovered)
			if nerr != nil {
				recovered.Close()
				os.Remove(recovered.Name())
				return nil, nil, "", false, nerr
			}
			return reg, func() { recovered.Close(); os.Remove(recovered.Name()) }, "recovered via .LOG replay", false, nil
		}
		reg, nerr := regparser.NewRegistry(hf)
		if nerr != nil {
			hf.Close()
			return nil, nil, "", false, nerr
		}
		return reg, func() { hf.Close() }, fmt.Sprintf("committed (.LOG replay failed: %v)", rerr), true, nil
	}
	reg, nerr := regparser.NewRegistry(hf)
	if nerr != nil {
		hf.Close()
		return nil, nil, "", false, nerr
	}
	return reg, func() { hf.Close() }, "committed", false, nil
}

func main() {
	var (
		file    = flag.String("f", "", "single hive (NTUSER.DAT / UsrClass.dat) to parse")
		dir     = flag.String("d", "", "directory to scan recursively for hives (regf)")
		jsonDir = flag.String("json", "", "directory to write JSONL output to (default: stdout)")
		jsonF   = flag.String("jsonf", "", "JSONL file name (default: SBECmd_Output.json)")
		workDir = flag.String("work-dir", os.TempDir(), "writable dir for the recovered hive during .LOG replay")
		nl      = flag.Bool("nl", false, "no transaction logs: skip dirty-hive .LOG1/.LOG2 replay")
		quiet   = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()

	if (*file == "") == (*dir == "") {
		fmt.Fprintln(os.Stderr, "gosbe: exactly one of -f <hive> or -d <dir> is required")
		flag.Usage()
		os.Exit(1)
	}
	dirMode := *dir != ""
	if dirMode {
		_ = os.MkdirAll(*workDir, 0o755)
	}
	inputs, err := collectInputs(*file, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gosbe: %v\n", err)
		os.Exit(1)
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "gosbe: no files found")
		os.Exit(1)
	}
	w, err := openOut(*jsonDir, *jsonF, "SBECmd_Output.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gosbe: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if w != os.Stdout {
			w.Close()
		}
	}()
	e := &emitter{enc: json.NewEncoder(w)}

	replay := !*nl
	failed, hives, bags := 0, 0, 0
	for _, p := range inputs {
		if dirMode && (isLogFile(p) || !looksLikeHive(p)) {
			continue
		}
		n, err := runHive(p, *workDir, replay, *quiet, e)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "gosbe: FAILED %s: %v\n", p, err)
			continue
		}
		hives++
		bags += n
		if !*quiet {
			fmt.Fprintf(os.Stderr, "gosbe: %s: %d shellbags\n", p, n)
		}
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "gosbe: %d shellbags across %d hive(s)\n", bags, hives)
	}
	if dirMode && hives == 0 && failed == 0 {
		fmt.Fprintf(os.Stderr, "gosbe: no registry hives found under %s\n", *dir)
		os.Exit(1)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "gosbe: %d hive(s) failed to parse\n", failed)
		os.Exit(2)
	}
}
