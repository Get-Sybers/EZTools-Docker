# GoDFIR-toolz

**Minimal hardened Docker images for Eric Zimmerman's forensic tools, built to
actually parse artefacts on Linux** — no shell, no python, no package manager,
uid0 renamed+locked, runs as uid 2000. One parameterized Dockerfile builds a
per-tool image for every Linux-viable EZ tool; a single all-in-one image
carries the whole family behind a static launcher; and the tools that
*cannot* work off-Windows are replaced by static Go parsers that read the same
artefacts natively.

## Coverage: the full EZ CLI family on Linux

| Requested tool | Image | Linux status |
| --- | --- | --- |
| **AmcacheParser** | **`get-sybers/goamcache` (Go substitute)** | ✅ Linux-viable under .NET, but ported to a static Go binary (regparser) to drop the .NET runtime — real-hive verified |
| **AppCompatCacheParser** | **`get-sybers/goappcompat` (Go substitute)** | ✅ Linux-viable under .NET, ported to a static Go binary (regparser) to drop .NET — real-SYSTEM-hive verified |
| bstrings | `get-sybers/bstrings` | ☑️ pure managed .NET — build-verified; parse-verify on first use |
| **EvtxECmd** | **`get-sybers/goevtx` (Go substitute)** | ✅ Linux-viable under .NET, but ported to a static Go binary (go-evtx) to drop the .NET runtime — real-.evtx verified end-to-end through byakugan's evtx maps |
| iisGeolocate | `get-sybers/iisgeolocate` | ☑️ pure managed .NET — mount/refresh its GeoLite2 `.mmdb` databases if the release doesn't bundle current ones |
| JLECmd | `get-sybers/jlecmd` | ✅ parse-verified |
| LECmd | `get-sybers/lecmd` | ✅ parse-verified |
| **MFTECmd** | **`get-sybers/gomft` (Go substitute)** | ✅ Linux-viable under .NET, but ported to a static Go binary (go-ntfs) to drop the .NET runtime — real-$MFT verified |
| **PECmd** | **`get-sybers/goprefetch` (Go substitute)** | ❌ PECmd itself cannot parse on Linux → `goprefetch` parses XP→Win11 `.pf` natively, MAM-compressed included |
| **RBCmd** | **`get-sybers/gorb` (Go substitute)** | ✅ Linux-viable under .NET, but ported to a static Go binary to drop the .NET runtime — parses v1/v2 `$I` records |
| RecentFileCacheParser | `get-sybers/recentfilecacheparser` | ☑️ pure managed .NET — build-verified; parse-verify on first use |
| RECmd | `get-sybers/recmd` | ✅ parse-verified (BatchExamples/ baked in) |
| RLA | `get-sybers/rla` | ☑️ pure managed .NET (same Registry library whose LOG replay already works on Linux via AppCompatCacheParser/SBECmd) |
| SBECmd | `get-sybers/sbecmd` | ✅ parse-verified (dirty hives need `.LOG1/.LOG2` alongside) |
| SQLECmd | `get-sybers/sqlecmd` | ✅ parse-verified (Maps/ baked in) |
| **SrumECmd** | **`get-sybers/goese` (Go substitute)** | ❌ SrumECmd cannot parse on Linux → `goese` parses SRUDB.dat natively with IdMap/SID enrichment |
| **SumECmd** | **`get-sybers/goese` (Go substitute)** | ❌ SumECmd cannot parse on Linux → `goese` reads SUM `Current.mdb` (any ESE database) |
| **VSCMount** | *(no container possible)* | ❌ manipulates the Windows VSS device namespace; on Linux use libvshadow (`vshadowinfo`/`vshadowmount`) on the host |
| WxTCmd | `get-sybers/wxtcmd` / all-in-one launcher | ✅ parse-verified — needs a writable exec `/tmp` (see below) |

### Why three tools are substituted, not packaged

"Installs on Linux" and "parses artefacts on Linux" are different claims.
Linux installer scripts for the EZ tools set up all 19 and validate them with
`--help` — which genuinely succeeds for every tool. But the four tools above
refuse at *parse* time, and (verified against v2026.5.0 built from upstream
source, run against real artefacts) they print their refusal and **exit 0**,
so a pipeline that only checks exit codes records a successful run that
produced nothing:

- **PECmd** — `Non-Windows platforms not supported due to the need to load
  decompression specific Windows libraries! Exiting...` on *any* input, even
  uncompressed XP-era prefetch (blanket guard in `Program.cs`; the Prefetch
  library P/Invokes `ntdll!RtlDecompressBufferEx` for Win8+/Win10 MAM files).
- **SrumECmd / SumECmd** — `Non-Windows platforms not supported due to the
  need to load ESI specific Windows libraries! Exiting...`; both depend on
  `Microsoft.Database.ManagedEsent`, a P/Invoke wrapper over Windows' native
  `esent.dll`.
- **VSCMount** — creates symlinks to
  `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`; the concept it
  manipulates does not exist off-Windows.

`eztool/Dockerfile` therefore fails fast if asked to build one of the four
(`--build-arg EZTOOL_ALLOW_WINDOWS_ONLY=1` overrides, e.g. to unpack a
release), and this repo ships native substitutes instead:

## The Go substitutes (FROM scratch, a few MB, no runtime at all)

### `get-sybers/goprefetch` — goprefetch (replaces PECmd)

Static Go binary on Velociraptor's `go-prefetch`, whose pure-Go
LZXpress-Huffman implementation decompresses Win8+/Win10/Win11 MAM prefetch on
any OS. Verified in this repo against real fixtures: WinXP, Vista, Win8.1,
Win10 and Win11 `.pf` files — all four MAM-compressed samples included — parse
correctly on Linux.

```sh
docker build -t get-sybers/goprefetch:latest -f goprefetch/Dockerfile goprefetch
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/goprefetch:latest -d /input --json /output
```

JSONL (or `--csv`) per file: `SourceFilename`, `Executable`, `Path`, `Hash`,
`Version`, `FileSize`, `RunCount`, `LastRun`, `PreviousRuns`,
`FilesAccessed`. Volume info blocks are the one PECmd output section not
emitted (not exposed by the library).

### `get-sybers/goese` — goese (replaces SrumECmd and SumECmd)

Static Go binary on Velociraptor's `go-ese` (pure-Go ESE). Verified in this
repo against a real 7.8 MB `SRUDB.dat`: all provider tables dumped (16k+ rows
in ApplicationResourceUsage), `SruDbIdMapTable` decoded automatically —
`AppId`/`UserId` columns gain `AppIdName`/`UserIdName` (UTF-16 strings, SIDs
for IdType 3), ESE DateTime columns arrive as RFC3339. Well-known SRUM
provider GUID tables get friendly output names (`ApplicationResourceUsage`,
`NetworkDataUsage`, `NetworkConnectivityUsage`, `EnergyUsage[LT]`,
`AppTimelineProvider`, `PushNotifications`); it reads SUM `Current.mdb` — or
any ESE database — the same way (`--list` shows tables).

```sh
docker build -t get-sybers/goese:latest -f goese/Dockerfile goese
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/goese:latest -f /input/SRUDB.dat --json /output
```

### `get-sybers/gorb` — gorb (replaces RBCmd)

Unlike PECmd/SrumECmd/SumECmd, RBCmd *does* parse on Linux under .NET — this
substitute exists to drop the .NET runtime, not to work around a Windows-only guard (the
`$I` metadata format is simple and fully specified, so a static Go binary is a
clean win; DX_DFIR #188 initiative 2). It parses the modern Recycle Bin `$I`
records — v1 (Vista–8.0, fixed 260-wchar path) and v2 (Win8.1/10/11,
length-prefixed path) — and emits RBCmd's columns (`SourceName`, `FileType`,
`FileName`, `FileSize`, `DeletedOn`) as CSV or JSONL. The legacy XP `INFO2`
container is not handled (obsolete, not in the pipeline's extraction filter).

`-d` finds records by their header, not their filename, so it picks up both a
raw-mount `$IXXXX` and Plaso's `image_export` rename (`$` → `_`, i.e. `_IXXXX`) —
the form the zimmerman lane actually feeds it. Parse-verified end to end on real
evidence: extracting `$Recycle.Bin` from a real acquisition with `image_export`
and running this image over the result recovers the deleted-file path, size and
deletion time.

```sh
docker build -t get-sybers/gorb:latest -f gorb/Dockerfile gorb
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/gorb:latest -d /input --csv /output --csvf gorb.csv
```

### `get-sybers/gomft` — gomft (replaces MFTECmd)

Like RBCmd, MFTECmd parses on Linux under .NET; this substitute drops the .NET
runtime with a static Go binary on Velociraptor's `go-ntfs`. It parses a raw
`$MFT` and emits one record per entry — entry/sequence, parent reference, file
name + extension, size, the `$STANDARD_INFORMATION` (0x10) and `$FILE_NAME`
(0x30) MACB timestamps, flags and ADS — as JSONL or CSV, mirroring MFTECmd's
columns. Fields go-ntfs does not expose (ReparseTarget, SecurityId, ObjectId,
ZoneId) are omitted, never faked. `-d` finds the table by its `FILE` signature,
so a raw-mount `$MFT` and Plaso's `image_export` rename (`_MFT`) both parse.
Parse-verified on a real 128 MB `$MFT` (130k entries: the NTFS metadata files at
entries 0–3, real system files resolved to their full paths and MACB times).

```sh
docker build -t get-sybers/gomft:latest -f gomft/Dockerfile gomft
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/gomft:latest -d /input --json /output --jsonf mftecmd.json
```

### `get-sybers/goamcache` — goamcache (replaces AmcacheParser)

Like RBCmd/MFTECmd, AmcacheParser parses on Linux under .NET; this substitute
drops the .NET runtime with a static Go binary on Velociraptor's `regparser`. It
parses an `Amcache.hve` and emits one record per program-execution file entry
(`Root\InventoryApplicationFile`) — the key's last-write time, ProgramId, the
SHA-1 (the `0000`-prefixed `FileId` stripped to the bare 40-hex hash), full path,
name, publisher/product/version and size — as CSV or JSONL, mirroring
AmcacheParser's `-i` columns. Dirty-hive `.LOG1/.LOG2` transaction logs **are
replayed** (`regparser.RecoverHive`) when they sit beside the hive, matching
AmcacheParser's fidelity; replay writes a recovered copy under `--work-dir`
(default `$TMPDIR`), which must be writable — mount a **tmpfs** there (the rootfs
is read-only). If the logs are absent or replay fails it falls back to the
committed hive with a stderr note (never a hard fail). Parse-verified on a real
Amcache.hve (237 entries — real program names, 40-hex SHA-1s, full paths and key
times; on this clean-shutdown image the `.LOG` replay was a no-op — 237 either way).

```sh
docker build -t get-sybers/goamcache:latest -f goamcache/Dockerfile goamcache
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/goamcache:latest -f /input/Amcache.hve --csv /output --csvf amcache.csv -i --work-dir /work
### `get-sybers/goappcompat` — goappcompat (replaces AppCompatCacheParser)

Like RBCmd/MFTECmd, AppCompatCacheParser parses on Linux under .NET; this
substitute drops the .NET runtime with a static Go binary on Velociraptor's
`regparser` (and its `appcompatcache` subpackage). It reads the AppCompatCache
(ShimCache) value from a SYSTEM hive and emits one record per entry — ControlSet,
CacheEntryPosition, Path, LastModifiedTimeUTC, SourceFile — as CSV or JSONL. The
.NET tool's Executed/Duplicate columns are not emitted (regparser's shimcache
parser does not expose that state — never faked). `-d` finds hives by their
`regf` signature; the pipeline calls `-f /in/SYSTEM`. Parse-verified on a real
SYSTEM hive (373 shimcache entries — real system32 executable paths + last-mod
times).

**Dirty-hive .LOG replay:** when `SYSTEM.LOG1/.LOG2` sit alongside the hive,
goappcompat recovers a copy (applies the journalled dirty pages via
`regparser.RecoverHive`) into `--work-dir` and parses that, matching the .NET
tool's fidelity. The recovered copy needs a **writable** work dir — the rootfs is
read-only, so mount a tmpfs and point `--work-dir` at it (`--tmpfs /tmp:...`; the
zimmerman lane wires this, like wxtcmd). No logs / unwritable work dir / recovery
error → it falls back to the committed hive with a one-line note (never
hard-fails).

```sh
docker build -t get-sybers/goappcompat:latest -f goappcompat/Dockerfile goappcompat
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/goappcompat:latest -f /input/SYSTEM --csv /output --csvf appcompatcache.csv
```

### `get-sybers/goevtx` — goevtx (replaces EvtxECmd)

Like RBCmd/MFTECmd, EvtxECmd parses on Linux under .NET; this substitute drops
the .NET runtime with a static Go binary on Velociraptor's `go-evtx`. It parses
`.evtx` and emits one JSON record per event in the EvtxECmd `*.json` shape the
DX_DFIR evtx lane and byakugan's winevt/evtx maps consume — `EventId`,
`Provider`, `Channel`, `Computer`, `EventRecordId`, `TimeCreated`, `Level`,
`UserId`, and `Payload` (the event's EventData rendered as the classic
`{"EventData":{"Data":[{"@Name","#text"}...]}}` form, or `{"UserData":...}`),
plus `SourceFile` and a null `MapDescription`. It does **not** reproduce
EvtxECmd's Maps layer (the per-provider YAML deriving `PayloadData1-6` /
`MapDescription`) — byakugan reads the raw EventData, not those derived columns,
so the substitute is faithful to what the pipeline consumes; those fields are
omitted, never faked. The `--xml` sidecar is a best-effort reconstruction for
manual review (not the original binary XML, and not ingested).

Parse-verified end to end on a real Sysmon `.evtx`: goevtx's output fed straight
through byakugan's `evtx_sysmon` map yielded correct CAR `process/create` and
`process/terminate` events (exe, pid/ppid, command line, integrity level,
SHA-256, ProcessGuid, parent links) for all 85 events.

```sh
docker build -t get-sybers/goevtx:latest -f goevtx/Dockerfile goevtx
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/goevtx:latest -f /input/Security.evtx --json /output \
  --jsonf Security_EvtxECmd_Output.json --xml /output --xmlf Security_EvtxECmd_Output.xml
```

All seven Go images are `FROM scratch`: one static binary, no shell, no python, no
libc, `USER 2000:2000` — the hardening contract holds by construction, and the
`docker export` scan verifies it the same way as for the .NET images.

## The per-tool recipe (unchanged posture, wider coverage)

`eztool/Dockerfile` fetches the published .NET release at build time (a
recipe, not a committed binary — the tools are MIT-licensed), verifies an
optional SHA-256 pin, bakes it into the official .NET runtime, runs the shared
Ansible hardener (`hardening/harden.yml`), then strips Ansible, apt, pip,
sudo, every shell and python itself out of the final image. The tool DLL is
the pinned ENTRYPOINT. The DLL inside each zip is located case-insensitively
(release zip layouts and casing vary — EvtxECmd ships an `EvtxeCmd/` dir, rla
ships `rla.dll`), and the run-as uid/gid honour the `DFIR_UID`/`DFIR_GID`
build args the DX_DFIR image role passes.

```sh
docker build -t get-sybers/recmd:latest    --build-arg EZTOOL=RECmd    -f eztool/Dockerfile .
docker build -t get-sybers/bstrings:latest --build-arg EZTOOL=bstrings -f eztool/Dockerfile .
# pin the release:
docker build -t get-sybers/sqlecmd:latest  --build-arg EZTOOL=SQLECmd \
  --build-arg EZTOOL_SHA256=<sha256 of SQLECmd.zip> -f eztool/Dockerfile .
# or everything at once:
./build-all.sh
```

## The all-in-one image (`eztools-all/`)

One image, every Linux-viable EZ tool, selected at **run** time — the
practical version of "the container adapts to the parser it's run with".
Hardening stays at build time (an immutable, read-only, root-less container
cannot meaningfully harden itself at runtime); what varies per run is which
parser the static Go launcher (`eztools-all/launcher/`) executes: the first
argument picks the tool case-insensitively, the rest is passed through, and
nothing else in the image is reachable via the entrypoint.

```sh
docker build -t get-sybers/eztools:latest -f eztools-all/Dockerfile .

docker run --rm get-sybers/eztools:latest list
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /tmp -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/eztools:latest EvtxECmd -d /input --csv /output
```

Why you'd want it over 15 per-tool images: one tag to pull, save and load for
offline/air-gapped use (one ~450 MB artefact instead of 15 × ~300 MB tars —
`docker save` only dedups shared base layers when you save all tags in a
single archive), one image warm in the cache across every lane, and per-tool
release pinning stays available via `eztools-all/checksums.sha256`.

**WxTCmd note** (applies to the per-tool image too): its SQLite interop
unpacks a native library beside the tool DLL, which a read-only rootfs
forbids. The launcher handles this — for WxTCmd it copies the tool to `/tmp`
and execs the copy — so run WxTCmd with a writable, exec-capable tmpfs:

```sh
  --tmpfs /tmp:rw,nosuid,nodev,exec,uid=2000,gid=2000,size=256m
```

(`EZTOOL_RUN_FROM_TMP=1|0` forces the behaviour on/off for any tool.)

## Two run modes

Every parser here is fed one of two ways, and the flags are the same shape in
both:

1. **A mounted disk image** — mount the image on the host (ewfmount/losetup +
   mount, or your image-export stage) and bind the filesystem root read-only
   into the container. `goprefetch -d /image` walks the whole tree for
   `*.pf`; `goese -d /image` finds every SRUM database (`SRUDB.dat`) and
   SUM database (`*.mdb` under a `SUM/` directory) case-insensitively and
   dumps each into its own sub-directory (`SRUM_SRUDB/`, `SUM_Current/`, …)
   with a `SourceDb` field on every row. The .NET tools that take `-d`
   (EvtxECmd, LECmd, JLECmd, SBECmd, …) can be pointed at the mounted root
   the same way.
2. **Extracted / loose files** — a staged directory of `.evtx`, hives, `.pf`,
   or a single database: same containers, `-d` at the staged directory or
   `-f` at the file.

## Parse-time efficiency: how to run these

The images are offline parsers — run them with nothing but mounts:

```sh
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /tmp -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/recmd:latest -d /input --bn /opt/eztool/BatchExamples/Kroll_Batch.reb --csv /output
```

Two things dominate wall-clock time on real evidence:

1. **Batch per directory, not per file.** Measured here: ~280–340 ms of
   container start overhead per `docker run` before any parsing, plus .NET
   assembly load/JIT warm-up per invocation. Every EZ tool takes `-d`; one
   container over a directory of 400 event logs pays that cost once instead
   of 400 times.
2. **The substitutes are cheap.** The Go images are 4–5 MB (vs ~300 MB for a
   .NET tool image), start as fast as the container runtime allows, and
   parsed the reference `SRUDB.dat` (10 tables, 27k rows, enrichment on) in
   under a second — artefact classes that previously had **no** working
   Linux container now cost less than any other lane.

## The hardening contract

`hardening/harden.yml` (Ansible, build-time only — Ansible itself is removed
afterwards) plus the Dockerfile's strip step leave each .NET image with:

- `USER 2000:2000` (or the `DFIR_UID`/`DFIR_GID` build args), uid0 renamed and
  locked
- no `apt`/`dpkg`/`pip`/`sudo`, no setuid binaries
- **no shell** (`sh`/`bash`/`dash` removed) and **no python**
- label `com.get-sybers.hardened=true` for downstream verification

The Go substitute images satisfy the same contract by construction (`FROM
scratch` — there is nothing to remove) and carry the same label. A consuming
pipeline can verify the contract without a shell in the image by exporting the
filesystem and asserting the absence of the removed binaries — that is exactly
what the DX_DFIR pipeline's image role does after every build.

## Linux run notes learned from real evidence

- **AppCompatCacheParser / SBECmd**: a dirty hive needs its transaction LOGs
  (`.LOG1`/`.LOG2`) extracted alongside, or the tool aborts.
- **WxTCmd**: see the tmpfs note above.
- **iisGeolocate**: keep its MaxMind `.mmdb` databases current — mount them
  read-only over the baked copies if the release's are stale.
- **Prefetch on Windows hosts**: PECmd remains the reference parser *on
  Windows*; `get-sybers/goprefetch` exists because Linux pipelines otherwise had to
  fall back to Plaso for `.pf`.

## License

MIT (this recipe and the Go tools). Eric Zimmerman's tools are themselves
MIT-licensed and are fetched from their published releases at build time;
`go-prefetch` and `go-ese` are Velociraptor components fetched as pinned Go
modules (`go.sum`) at build time.
