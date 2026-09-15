"""piiat_mem_batch — the get-sybers/piiat-mem container's ENTRYPOINT.

Self-orchestrating, driven ENTIRELY by environment variables, so a caller (the
DX_DFIR ansible volatility lane) does nothing but

    docker run --rm -e PIIAT_... -v <mem>:/mem:ro -v <out>:/out -v <isf>:/symbols \
        get-sybers/piiat-mem

with no wrapper on the host. Everything that used to live in DX_DFIR's
``get_sybers_dxdfir.volatility`` module (discover the images, decide per plugin
what still needs running, invoke PIIAT-Mem, judge success per output file, emit
a machine-readable summary) now lives HERE, inside the hardened image.

PIIAT-Mem itself is consumed through its PUBLIC CLI (``python3 -m piiat_mem
--native -f <image> -o <dest> --plugins ... --symbols ... --no-timeline``) — one
invocation per memory image, never by importing its internals. Volatility 3 runs
in-process inside that invocation (``--native``), confined by this image.

Ideally this batch mode belongs in PIIAT-Mem itself (``piiat-mem --batch <dir>``);
until it grows one, the image carries this orchestrator.

ENV-VAR CONTRACT (all optional; the defaults match the mount points)
--------------------------------------------------------------------
  PIIAT_MEMORY_DIR     directory tree of memory images, recursed   (default /mem)
  PIIAT_OUT_DIR        output root; one folder per image           (default /out)
  PIIAT_SYMBOLS_DIR    Volatility ISF symbol cache, read-write     (default /symbols)
  PIIAT_PLUGINS        comma-separated Volatility plugin names; empty/unset = the
                       default CAR set (DEFAULT_PLUGINS below)
  PIIAT_FORCE          1/true/yes/on: rerun plugins that already have valid output
                       (default 0: per-plugin idempotent)
  PIIAT_SYMBOLS_ONLINE 1/true/yes/on: the caller has given THIS container network
                       so Windows plugins can fetch ISF symbols on first use.
                       INFORMATIONAL — recorded in the summary/log; the container's
                       network (``docker run --network``) is what actually gates
                       the fetch. Default 0 (offline: pre-seed PIIAT_SYMBOLS_DIR).

OUTPUT CONTRACT
---------------
  <out>/<clean image name>/plugins/<plugin>.jsonl   raw per-plugin JSON Lines
  <out>/<clean image name>/piiat_mem.log            that image's full PIIAT-Mem
                                                    stdout+stderr (overwritten per run)
  stdout                                            ONE line: the JSON summary
  stderr                                            progress + diagnostics (log tails)

  <clean image name> = the image's path relative to PIIAT_MEMORY_DIR with "/" and
  " " folded to "_" (two corpora sharing a basename keep distinct output).

SUMMARY (stdout, one JSON object)
  {"tool": "piiat-mem", "memory_dir", "out_dir", "symbols_dir", "symbols_online",
   "force", "images": <n found>, "plugins": <n requested>, "processed": <plugin
   outputs newly produced>, "skipped": <plugin outputs already valid>, "failed":
   <plugin outputs empty/invalid>, "results": [{"image": <rel path>, "produced":
   [...], "empty": [...]}, ...], ["diagnostics": <log tails, when nothing at all
   was produced>], ["error": <message>]}

EXIT CODE
  0  normal (including a fully idempotent re-run: everything skipped)
  1  the run produced nothing, nothing was already done, and something failed
     (the retryable Windows-without-symbols case)
  2  a configuration or summary-level error (memory dir missing / output dir
     unwritable / any summary "error")

Idempotency: a plugin whose ``<dest>/plugins/<plugin>.jsonl`` exists and whose
first line parses as JSON is done (also honoured: the legacy flat
``<dest>/<plugin>.jsonl`` an earlier DX_DFIR lane wrote). Only the still-missing
plugins are passed to ``--plugins``; an image with none missing is not invoked at
all. Empty/failed outputs are removed, never counted as done.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections import deque

TOOL = "piiat-mem"

# A Volatility plugin name is a dotted identifier (e.g. windows.pslist,
# banners.Banners) — never a path. This anchors what may be interpolated into an
# output path, so a caller can't smuggle path separators / traversal (../) into
# PIIAT_PLUGINS and steer the per-plugin write/cleanup off <dest>/plugins.
_PLUGIN_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.]*\Z")

# The CAR plugin set, by PIIAT-Mem's PUBLIC plugin names (its CLI interface).
# banners.Banners runs first — format-agnostic, it sanity-checks the image
# without symbols. Car* comments show the downstream CAR artefact each maps to.
DEFAULT_PLUGINS = [
    "banners.Banners",
    "windows.info",
    "windows.piiat.processes",        # -> CarProcess (psscan; token Sid/User/LogonId)
    "windows.pslist",
    "windows.pstree",
    "windows.piiat.modules",          # -> CarModule (OwnerOffset: definitive link)
    "windows.modules",                # -> CarDriver
    "windows.piiat.network",          # -> CarFlow / socket (OwnerOffset)
    "windows.netstat",                # -> CarFlow (second view)
    "windows.piiat.sessions",         # -> CarUserSession (token LUID logons)
    "windows.filescan",               # -> CarFile (ownerless scan)
    "windows.piiat.files",            # -> CarFile (handle-enumerated, WITH owners)
    "windows.svcscan",                # -> CarService
    "windows.piiat.threads",          # -> CarThread (OwnerOffset + stacks)
    "windows.piiat.registry",         # -> CarRegistry
    "windows.piiat.access",           # -> CarProcess access events (handle-observed)
    "windows.mftscan.MFTScan",        # -> CarFile (NTFS times from resident $MFT)
    "windows.malfind",
]

_MEMORY_EXTS = (
    ".raw", ".mem", ".dmp", ".lime", ".vmem",
    ".bin", ".dump", ".vmsn", ".crash",
)

_TRUE = {"1", "true", "yes", "on"}


# --- env ---------------------------------------------------------------------

def env_str(name: str, default: str) -> str:
    val = os.environ.get(name, "")
    return val if val.strip() else default


def env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE


def env_plugins() -> list[str]:
    raw = os.environ.get("PIIAT_PLUGINS", "")
    safe = []
    for p in (p.strip() for p in raw.split(",") if p.strip()):
        if _PLUGIN_RE.match(p):
            safe.append(p)
        else:
            sys.stderr.write(f"[{TOOL}] ignoring invalid plugin name {p!r} — a "
                             "Volatility plugin id is dotted letters/digits/._, not a path\n")
    return safe or list(DEFAULT_PLUGINS)


# --- discovery ---------------------------------------------------------------

def is_memory_image(name: str) -> bool:
    """Match by common memory-dump extensions plus the M57 corpus '*dramimage'."""
    low = name.lower()
    return low.endswith(_MEMORY_EXTS) or low.endswith("dramimage")


def discover(memory_dir: str) -> list[str]:
    """Every memory image under memory_dir (recursed), sorted, absolute. Symlinks
    are neither followed (dirs) nor listed (files): the evidence mount is what it
    is, and a link can't point the tool outside it."""
    found = []
    for root, dirs, files in os.walk(memory_dir, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
        for name in files:
            path = os.path.join(root, name)
            if is_memory_image(name) and not os.path.islink(path) and os.path.isfile(path):
                found.append(path)
    return sorted(found)


def clean_name(rel: str) -> str:
    """Output-folder name from a path relative to the memory dir (dirs+space folded),
    so two corpora sharing a basename keep distinct output."""
    return rel.replace("/", "_").replace(" ", "_")


# --- per-plugin done/valid ---------------------------------------------------

def _valid_jsonl(path: str) -> bool:
    """Non-empty and first line parses as JSON — the done/valid guard."""
    try:
        if os.path.getsize(path) <= 0:
            return False
        with open(path, encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
    except OSError:
        return False
    if not first.strip():
        return False
    try:
        json.loads(first)
        return True
    except json.JSONDecodeError:
        return False


def _out_path(dest: str, plugin: str) -> str:
    """Where PIIAT-Mem writes a plugin's JSONL: <dest>/plugins/<plugin>.jsonl."""
    return os.path.join(dest, "plugins", f"{plugin}.jsonl")


def _plugin_done(dest: str, plugin: str) -> bool:
    """Valid output at the tool's path OR the legacy flat ``<dest>/<plugin>.jsonl``
    an earlier lane version wrote — upgrading doesn't re-run every corpus."""
    return _valid_jsonl(_out_path(dest, plugin)) or _valid_jsonl(os.path.join(dest, f"{plugin}.jsonl"))


def _tail(path: str, n: int) -> str:
    """Last ``n`` lines of a text file, or "" if unreadable — for diagnostics.
    A deque(maxlen=n) keeps only the last n lines in memory, so a multi-GB
    piiat_mem.log doesn't spike memory when diagnostics are emitted."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = deque(fh, maxlen=n)
    except OSError:
        return ""
    return "".join(lines).rstrip()


# --- one PIIAT-Mem run -------------------------------------------------------

def _log(msg: str) -> None:
    sys.stderr.write(f"[{TOOL}] {msg}\n")
    sys.stderr.flush()


def run_piiat_mem(img: str, dest: str, plugins: list[str], symbols_dir: str) -> int:
    """One ``python3 -m piiat_mem --native`` run for ``plugins`` over ``img`` into
    ``dest``; its stdout+stderr are STREAMED to ``<dest>/piiat_mem.log`` so a
    big/verbose run stays bounded and debuggable and our own stdout stays a clean
    summary. The exit code is returned but NOT gated on — rc=1 just means every
    plugin produced nothing (the retryable Windows-without-symbols case); success
    is judged per file by ``_valid_jsonl``."""
    argv = [sys.executable, "-m", "piiat_mem", "--native",
            "-f", img, "-o", dest,
            "--plugins", ",".join(plugins),   # bare commas: the CLI splits on "," with no strip
            "--symbols", symbols_dir,
            "--no-timeline"]                   # raw per-plugin JSONL only; DX_DFIR timelines downstream
    header = (f"[{TOOL}] {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
              f"image={img} dest={dest} plugins={','.join(plugins)}\n"
              f"[{TOOL}] argv: {' '.join(argv)}\n")
    with open(os.path.join(dest, "piiat_mem.log"), "wb") as log:
        log.write(header.encode("utf-8"))
        log.flush()
        proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=False)
        log.write(f"[{TOOL}] piiat_mem exit code {proc.returncode}\n".encode("utf-8"))
    return proc.returncode


# --- batch -------------------------------------------------------------------

def process(memory_dir: str, out_dir: str, symbols_dir: str, plugins: list[str],
            force: bool, symbols_online: bool) -> dict:
    """Run the plugin set over every image under memory_dir. Idempotent per plugin."""
    summary = {
        "tool": TOOL,
        "memory_dir": memory_dir,
        "out_dir": out_dir,
        "symbols_dir": symbols_dir,
        "symbols_online": symbols_online,
        "force": force,
        "images": 0,
        "plugins": len(plugins),
        "processed": 0, "skipped": 0, "failed": 0,
        "results": [],
    }
    if not os.path.isdir(memory_dir):
        summary["error"] = f"memory dir not found or not a directory: {memory_dir} (mount it, or set PIIAT_MEMORY_DIR)"
        return summary
    try:
        os.makedirs(out_dir, exist_ok=True)
        probe = os.path.join(out_dir, ".piiat-mem-write-probe")
        with open(probe, "w") as fh:
            fh.write("")
        os.remove(probe)
    except OSError as exc:
        summary["error"] = f"output dir not writable by uid {os.getuid()}: {out_dir} ({exc})"
        return summary
    # /symbols is a caller-provided bind mount where Volatility caches fetched ISF
    # symbols; the caller must mount it writable by this image's uid. We do NOT
    # chmod it — that would mutate the permissions of the host path behind the
    # bind mount. A pre-seeded, read-only symbol tree is fine for offline runs.
    try:
        os.makedirs(symbols_dir, exist_ok=True)
    except OSError:
        pass

    images_found = discover(memory_dir)
    summary["images"] = len(images_found)
    _log(f"memory_dir={memory_dir} out_dir={out_dir} symbols_dir={symbols_dir} "
         f"symbols_online={int(symbols_online)} force={int(force)} "
         f"plugins={len(plugins)} images={len(images_found)}")

    processed = skipped = failed = 0
    for idx, img in enumerate(images_found, 1):
        rel = os.path.relpath(img, memory_dir)
        dest = os.path.join(out_dir, clean_name(rel))
        os.makedirs(dest, exist_ok=True)
        per_image = {"image": rel, "produced": [], "empty": []}

        todo = []
        for plugin in plugins:
            if not force and _plugin_done(dest, plugin):
                skipped += 1
            else:
                todo.append(plugin)

        if todo:  # never invoke with an empty --plugins (the CLI would run ITS default set)
            _log(f"image {idx}/{len(images_found)}: {rel} — running {len(todo)} plugin(s)"
                 f" ({len(plugins) - len(todo)} already done)")
            rc = run_piiat_mem(img, dest, todo, symbols_dir)
            for plugin in todo:
                out_path = _out_path(dest, plugin)
                if _valid_jsonl(out_path):
                    processed += 1
                    per_image["produced"].append(plugin)
                else:
                    if os.path.exists(out_path):
                        os.remove(out_path)
                    failed += 1
                    per_image["empty"].append(plugin)
            _log(f"image {idx}/{len(images_found)}: {rel} — produced {len(per_image['produced'])},"
                 f" empty {len(per_image['empty'])} (piiat_mem rc={rc})")
        else:
            _log(f"image {idx}/{len(images_found)}: {rel} — all {len(plugins)} plugin(s) already done")
        summary["results"].append(per_image)

    summary.update(processed=processed, skipped=skipped, failed=failed)
    # When nothing produced output for any image, the real cause is buried in the
    # per-image log. Surface the tails (of the images that failed THIS run — not
    # of ones that were skipped as already done) so the caller sees WHY.
    if images_found and processed == 0 and failed > 0:
        tails = []
        for per_image in summary["results"]:
            if not per_image["empty"]:
                continue
            log_path = os.path.join(out_dir, clean_name(per_image["image"]), "piiat_mem.log")
            tail = _tail(log_path, 20)
            if tail:
                tails.append(f"--- {per_image['image']} (last lines of piiat_mem.log) ---\n{tail}")
        if tails:
            summary["diagnostics"] = "\n".join(tails)
    return summary


def main(argv: list[str]) -> int:
    # Any CLI argument = pass-through to PIIAT-Mem's own single-image CLI (the
    # previous run shape, e.g. `docker run ... get-sybers/piiat-mem -f /mem/x -o
    # /out --symbols /symbols`); --native is still forced. No args = batch mode.
    if argv:
        os.execv(sys.executable, [sys.executable, "-m", "piiat_mem", "--native", *argv])

    summary = process(
        memory_dir=env_str("PIIAT_MEMORY_DIR", "/mem"),
        out_dir=env_str("PIIAT_OUT_DIR", "/out"),
        symbols_dir=env_str("PIIAT_SYMBOLS_DIR", "/symbols"),
        plugins=env_plugins(),
        force=env_bool("PIIAT_FORCE"),
        symbols_online=env_bool("PIIAT_SYMBOLS_ONLINE"),
    )
    # Diagnostics go to stderr so a non-zero rc surfaces the REAL cause; stdout
    # is the one-line summary the caller parses.
    if summary.get("error"):
        sys.stderr.write(summary["error"] + "\n")
    if summary.get("diagnostics"):
        sys.stderr.write(summary["diagnostics"] + "\n")
    sys.stderr.flush()
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()
    if summary.get("error"):
        return 2
    # Fail only when the run produced nothing AND nothing was already done: inputs
    # that can never produce output are retried on every run, and must not flip
    # an otherwise-complete, idempotent re-run into a failure.
    return 1 if summary["failed"] and not summary["processed"] and not summary["skipped"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
