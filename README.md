# EZTools-Docker

**Minimal hardened Docker images for Eric Zimmerman's forensic tools** — one
parameterized Dockerfile builds the whole family, each image carrying nothing
but the tool: **no shell, no python, no package manager, uid0 renamed+locked,
runs as uid 2000**.

## The recipe

`eztool/Dockerfile` fetches the published .NET release at build time (a recipe,
not a committed binary — the tools are MIT-licensed), verifies an optional
SHA-256 pin, bakes it into the official .NET runtime, runs the shared Ansible
hardener (`hardening/harden.yml`), then strips Ansible, apt, pip, sudo, every
shell and python itself out of the final image. The tool DLL is the pinned
ENTRYPOINT (the dll + runtimeconfig + deps trio is linked under a stable name
so `dotnet /opt/eztool/tool.dll` works for any tool).

```sh
docker build -t dfir/recmd:latest     --build-arg EZTOOL=RECmd     -f eztool/Dockerfile .
docker build -t dfir/srumecmd:latest  --build-arg EZTOOL=SrumECmd  -f eztool/Dockerfile .
# pin the release:
docker build -t dfir/mftecmd:latest   --build-arg EZTOOL=MFTECmd \
  --build-arg EZTOOL_SHA256=<sha256 of MFTECmd.zip> -f eztool/Dockerfile .
```

Verified tool matrix (all build from the one Dockerfile, all parse-verified on
Linux): RECmd, MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, LECmd,
JLECmd, SBECmd, SQLECmd, RBCmd, WxTCmd.

**SrumECmd builds but is Windows-host-only**: its shipped assembly embeds
ManagedEsent (`Esent.Interop`), a P/Invoke wrapper around Windows' native ESE
engine (`esent.dll`) — an OS component that does not exist on Linux, so the
tool refuses at database-open time ("Non-Windows platforms not supported...").
Verified empirically: it is the ONLY tool in the family with that dependency.
On a Linux pipeline, parse SRUDB.dat with Plaso's `esedb/srum` parser instead
(libesedb — a pure cross-platform ESE implementation): the same artefact
yields the same data. Tools that ship data sets alongside the DLL keep them
(RECmd's `BatchExamples/`, SQLECmd's `Maps/`) at `/opt/eztool/`.

`evtxecmd/Dockerfile` is the original, EvtxECmd-specific build (bakes `Maps/`;
same posture) that the parameterized recipe generalises.

## Running

The images are offline parsers — run them with nothing but mounts:

```sh
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /tmp -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  dfir/recmd:latest -d /input --bn /opt/eztool/BatchExamples/Kroll_Batch.reb --csv /output
```

## The hardening contract

`hardening/harden.yml` (Ansible, build-time only — Ansible itself is removed
afterwards) plus the Dockerfile's strip step leave each image with:

- `USER 2000:2000`, uid0 renamed and locked
- no `apt`/`dpkg`/`pip`/`sudo`, no setuid binaries
- **no shell** (`sh`/`bash`/`dash` removed) and **no python**
- label `com.get-sybers.hardened=true` for downstream verification

A consuming pipeline can verify the contract without a shell in the image by
exporting the filesystem and asserting the absence of the removed binaries —
that is exactly what the DX_DFIR pipeline's image role does after every build.

## License

MIT (this recipe). Eric Zimmerman's tools are themselves MIT-licensed and are
fetched from their published releases at build time.
