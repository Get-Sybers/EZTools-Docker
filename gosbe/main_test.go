package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(strings.Join(strings.Fields(s), ""), " ", ""))
	if err != nil {
		t.Fatalf("unhex: %v", err)
	}
	return b
}

func TestDecodeGUID(t *testing.T) {
	// little-endian mixed GUID for "My Computer"
	b := unhex(t, "e04fd020ea3a6910a2d808002b30309d")
	if got := decodeGUID(b); got != "20d04fe0-3aea-1069-a2d8-08002b30309d" {
		t.Errorf("decodeGUID = %q", got)
	}
}

func TestDecodeShellItem_GUIDFolder(t *testing.T) {
	// real 0x1F "My Computer" item from a UsrClass.dat BagMRU
	item := unhex(t, "14001f50e04fd020ea3a6910a2d808002b30309d0000")
	name, th := decodeShellItem(item)
	if name != "My Computer" || th != "0x1F" {
		t.Errorf("decodeShellItem(0x1F) = %q, %q", name, th)
	}
}

func TestDecodeShellItem_Volume(t *testing.T) {
	// size(2) + type 0x2F + "C:\\\0"
	item := unhex(t, "07002f433a5c00")
	name, th := decodeShellItem(item)
	if name != `C:\` || th != "0x2F" {
		t.Errorf("decodeShellItem(0x2F) = %q, %q", name, th)
	}
}

func TestDecodeShellItem_FileEntry_BEEFLongName(t *testing.T) {
	// a real 0x31 directory item from a live UsrClass.dat BagMRU: an ANSI short
	// name ("patcher") at offset 14 plus a BEEF0004 version-9 extension block
	// whose UTF-16LE long name sits at block+46. Verbatim hive bytes.
	item := unhex(t, "5600310000000000585a651c1000706174636865720040"+
		"0009000400efbe585abc1b585adc1c2e000000679901000000010000000000"+
		"000000000000000000000ff29e007000610074006300680065007200000016000000")
	name, th := decodeShellItem(item)
	if th != "0x31" {
		t.Fatalf("shell type = %q, want 0x31", th)
	}
	if name != "patcher" {
		t.Errorf("file-entry long name = %q, want patcher", name)
	}
}

func TestDecodeShellItem_UndecodedTypeNoInventedName(t *testing.T) {
	// a property/delegate item (0x00): emit the type, never a made-up name
	item := unhex(t, "0800000abcdef012")
	name, th := decodeShellItem(item)
	if name != "" {
		t.Errorf("undecoded item name = %q, want empty", name)
	}
	if th != "0x00" {
		t.Errorf("undecoded item type = %q", th)
	}
}

func TestIsCleanName(t *testing.T) {
	for _, ok := range []string{"Users", "patcher", "Wondershare Filmora", "survey.zip", "café"} {
		if !isCleanName(ok) {
			t.Errorf("isCleanName(%q) = false, want true", ok)
		}
	}
	// misaligned-UTF16 junk (high CJK codepoints) must be rejected
	for _, bad := range []string{"\u1cdc.", "\u2d29\u3a90", ""} {
		if isCleanName(bad) {
			t.Errorf("isCleanName(%q) = true, want false", bad)
		}
	}
}

func TestNumericHelpers(t *testing.T) {
	if !isNumeric("0") || !isNumeric("42") || isNumeric("") || isNumeric("1a") {
		t.Error("isNumeric wrong")
	}
	if atoiSafe("0") != 0 || atoiSafe("42") != 42 || atoiSafe("007") != 7 {
		t.Error("atoiSafe wrong")
	}
}
