// eztool launcher — static entrypoint for the all-in-one EZ Tools image.
//
// The image is hardened at BUILD time (immutable, read-only rootfs, no shell,
// uid 2000); what varies per run is only WHICH parser executes. The first
// argument selects the tool (case-insensitive match against the directories
// under /opt/eztools) and the launcher execs `dotnet <that tool's DLL>` with
// the remaining arguments — nothing else in the image is reachable through
// the entrypoint.
//
//	docker run … dfir/eztools:latest EvtxECmd -f /input/Security.evtx --csv /output
//	docker run … dfir/eztools:latest list
//
// Tools whose SQLite interop unpacks a native library next to the DLL
// (WxTCmd) cannot run from the read-only /opt/eztools; for those the launcher
// copies the tool directory into $TMPDIR first and execs the copy — run the
// container with a writable, exec-capable /tmp:
//
//	--tmpfs /tmp:rw,nosuid,nodev,exec,uid=2000,gid=2000,size=256m
//
// Override with EZTOOL_RUN_FROM_TMP=1|0. EZTOOL_ROOT and EZTOOL_DOTNET
// override the tool root and dotnet path (mainly for tests).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// runFromTmpDefault lists tools that must run from a writable directory.
var runFromTmpDefault = map[string]bool{
	"wxtcmd": true,
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func listTools(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var tools []string
	for _, e := range entries {
		if e.IsDir() {
			tools = append(tools, e.Name())
		}
	}
	sort.Strings(tools)
	return tools
}

// findDLL locates <dir>/<name>.dll case-insensitively (zip casing varies).
func findDLL(dir, name string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	want := strings.ToLower(name) + ".dll"
	for _, e := range entries {
		if !e.IsDir() && strings.ToLower(e.Name()) == want {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

func usage(root string, code int) {
	fmt.Fprintln(os.Stderr, "usage: eztool <tool> [tool arguments...]")
	fmt.Fprintln(os.Stderr, "available tools:")
	for _, t := range listTools(root) {
		fmt.Fprintln(os.Stderr, "  "+t)
	}
	os.Exit(code)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "eztool: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	root := env("EZTOOL_ROOT", "/opt/eztools")
	dotnet := env("EZTOOL_DOTNET", "/usr/bin/dotnet")

	if len(os.Args) < 2 {
		usage(root, 64)
	}
	if os.Args[1] == "list" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		usage(root, 0)
	}

	requested := os.Args[1]
	toolDir := ""
	toolName := ""
	for _, t := range listTools(root) {
		if strings.EqualFold(t, requested) {
			toolDir = filepath.Join(root, t)
			toolName = t
			break
		}
	}
	if toolDir == "" {
		fmt.Fprintf(os.Stderr, "eztool: unknown tool %q\n", requested)
		usage(root, 64)
	}

	fromTmp := runFromTmpDefault[strings.ToLower(toolName)]
	switch os.Getenv("EZTOOL_RUN_FROM_TMP") {
	case "1", "true", "yes":
		fromTmp = true
	case "0", "false", "no":
		fromTmp = false
	}
	if fromTmp {
		dst := filepath.Join(env("TMPDIR", "/tmp"), "eztool-"+strings.ToLower(toolName))
		if err := os.RemoveAll(dst); err != nil {
			fatal("cannot clear %s: %v", dst, err)
		}
		if err := os.CopyFS(dst, os.DirFS(toolDir)); err != nil {
			fatal("cannot copy %s to writable %s (is /tmp a writable tmpfs?): %v",
				toolDir, dst, err)
		}
		toolDir = dst
	}

	dll := findDLL(toolDir, toolName)
	if dll == "" {
		fatal("no %s.dll under %s", toolName, toolDir)
	}

	argv := append([]string{dotnet, dll}, os.Args[2:]...)
	if err := syscall.Exec(dotnet, argv, os.Environ()); err != nil {
		fatal("exec %s: %v", dotnet, err)
	}
}
