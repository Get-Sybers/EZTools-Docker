# EZTools-Docker

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
| AmcacheParser | `dfir/amcacheparser` (or all-in-one) | ✅ parse-verified on real evidence |
| AppCompatCacheParser | `dfir/appcompatcacheparser` | ✅ parse-verified (dirty hives need `.LOG1/.LOG2` alongside) |
| bstrings | `dfir/bstrings` | ☑️ pure managed .NET — build-verified; parse-verify on first use |
| EvtxECmd | `dfir/evtxecmd` | ✅ parse-verified (Maps/ baked in) |
| iisGeolocate | `dfir/iisgeolocate` | ☑️ pure managed .NET — mount/refresh its GeoLite2 `.mmdb` databases if the release doesn't bundle current ones |
| JLECmd | `dfir/jlecmd` | ✅ parse-verified |
| LECmd | `dfir/lecmd` | ✅ parse-verified |
| MFTECmd | `dfir/mftecmd` | ✅ parse-verified |
| **PECmd** | **`dfir/prefetch` (Go substitute)** | ❌ PECmd itself cannot parse on Linux → `prefetch_dump` parses XP→Win11 `.pf` natively, MAM-compressed included |
| RBCmd | `dfir/rbcmd` | ✅ parse-verified |
| RecentFileCacheParser | `dfir/recentfilecacheparser` | ☑️ pure managed .NET — build-verified; parse-verify on first use |
| RECmd | `dfir/recmd` | ✅ parse-verified (BatchExamples/ baked in) |
| RLA | `dfir/rla` | ☑️ pure managed .NET (same Registry library whose LOG replay already works on Linux via AppCompatCacheParser/SBECmd) |
| SBECmd | `dfir/sbecmd` | ✅ parse-verified (dirty hives need `.LOG1/.LOG2` alongside) |
| SQLECmd | `dfir/sqlecmd` | ✅ parse-verified (Maps/ baked in) |
| **SrumECmd** | **`dfir/esedump` (Go substitute)** | ❌ SrumECmd cannot parse on Linux → `ese_dump` parses SRUDB.dat natively with IdMap/SID enrichment |
| **SumECmd** | **`dfir/esedump` (Go substitute)** | ❌ SumECmd cannot parse on Linux → `ese_dump` reads SUM `Current.mdb` (any ESE database) |
| **VSCMount** | *(no container possible)* | ❌ manipulates the Windows VSS device namespace; on Linux use libvshadow (`vshadowinfo`/`vshadowmount`) on the host |
| WxTCmd | `dfir/wxtcmd` / all-in-one launcher | ✅ parse-verified — needs a writable exec `/tmp` (see below) |

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

### `dfir/prefetch` — prefetch_dump (replaces PECmd)

Static Go binary on Velociraptor's `go-prefetch`, whose pure-Go
LZXpress-Huffman implementation decompresses Win8+/Win10/Win11 MAM prefetch on
any OS. Verified in this repo against real fixtures: WinXP, Vista, Win8.1,
Win10 and Win11 `.pf` files — all four MAM-compressed samples included — parse
correctly on Linux.

```sh
docker build -t dfir/prefetch:latest -f prefetch/Dockerfile prefetch
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  dfir/prefetch:latest -d /input --json /output
```

JSONL (or `--csv`) per file: `SourceFilename`, `Executable`, `Path`, `Hash`,
`Version`, `FileSize`, `RunCount`, `LastRun`, `PreviousRuns`,
`FilesAccessed`. Volume info blocks are the one PECmd output section not
emitted (not exposed by the library).

### `dfir/esedump` — ese_dump (replaces SrumECmd and SumECmd)

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
docker build -t dfir/esedump:latest -f srum/Dockerfile srum
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  dfir/esedump:latest -f /input/SRUDB.dat --json /output
```

Both images are `FROM scratch`: one static binary, no shell, no python, no
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
docker build -t dfir/recmd:latest    --build-arg EZTOOL=RECmd    -f eztool/Dockerfile .
docker build -t dfir/bstrings:latest --build-arg EZTOOL=bstrings -f eztool/Dockerfile .
# pin the release:
docker build -t dfir/mftecmd:latest  --build-arg EZTOOL=MFTECmd \
  --build-arg EZTOOL_SHA256=<sha256 of MFTECmd.zip> -f eztool/Dockerfile .
# or everything at once:
./build-all.sh
```

`evtxecmd/Dockerfile` is the original, EvtxECmd-specific build (bakes `Maps/`;
same posture) that the parameterized recipe generalises.

## The all-in-one image (`eztools-all/`)

One image, every Linux-viable EZ tool, selected at **run** time — the
practical version of "the container adapts to the parser it's run with".
Hardening stays at build time (an immutable, read-only, root-less container
cannot meaningfully harden itself at runtime); what varies per run is which
parser the static Go launcher (`eztools-all/launcher/`) executes: the first
argument picks the tool case-insensitively, the rest is passed through, and
nothing else in the image is reachable via the entrypoint.

```sh
docker build -t dfir/eztools:latest -f eztools-all/Dockerfile .

docker run --rm dfir/eztools:latest list
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /tmp -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  dfir/eztools:latest EvtxECmd -d /input --csv /output
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

## Parse-time efficiency: how to run these

The images are offline parsers — run them with nothing but mounts:

```sh
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /tmp -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  dfir/recmd:latest -d /input --bn /opt/eztool/BatchExamples/Kroll_Batch.reb --csv /output
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
  Windows*; `dfir/prefetch` exists because Linux pipelines otherwise had to
  fall back to Plaso for `.pf`.

## License

MIT (this recipe and the Go tools). Eric Zimmerman's tools are themselves
MIT-licensed and are fetched from their published releases at build time;
`go-prefetch` and `go-ese` are Velociraptor components fetched as pinned Go
modules (`go.sum`) at build time.
