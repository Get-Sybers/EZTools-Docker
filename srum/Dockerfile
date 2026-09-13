# syntax=docker/dockerfile:1
#
# ese_dump — Linux-native ESE database dumper (SrumECmd's and SumECmd's Linux
# substitute) for the DX_DFIR pipeline.
#
# SrumECmd and SumECmd are Windows-host-only (verified empirically, source and
# runtime: both read ESE databases through Microsoft.Database.ManagedEsent, a
# P/Invoke wrapper over Windows' native esent.dll, and exit "Non-Windows
# platforms not supported due to the need to load ESI specific Windows
# libraries!" with status 0). This image ships a static Go binary built on
# Velociraptor's go-ese, a pure-Go ESE implementation: SRUDB.dat and SUM
# databases (Current.mdb / SystemIdentity.mdb) parse on Linux, with SRUM
# IdMap enrichment (AppIdName / UserIdName incl. SID decoding) built in.
#
# The final image is FROM scratch: one static binary, nothing else. The
# hardening contract is met by construction — no shell, no python, no package
# manager, no setuid, no libc even; runs as uid 2000.
#
#   docker build -t get-sybers/esedump:latest -f srum/Dockerfile srum
#
# Mode 2 — one extracted database:
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/esedump:latest -f /input/SRUDB.dat --json /output
#
# Mode 1 — a mounted disk image root (finds every SRUM/SUM database, dumps
# each into its own sub-directory, rows carry SourceDb):
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v /mnt/image:/image:ro -v "$PWD/out:/output" \
#     get-sybers/esedump:latest -d /image --json /output
#
# Output: one JSONL (or --csv) file per table; well-known SRUM provider GUID
# tables get friendly file names (ApplicationResourceUsage, NetworkDataUsage,
# ...). --list shows tables and columns. Works on any ESE database.

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /ese_dump . \
    && /ese_dump -f /dev/null 2>/dev/null || true

FROM scratch
COPY --from=build /ese_dump /ese_dump
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
# Single run-as uid/gid, passed by the DX_DFIR image role (dxdfir_runtime_uid/gid)
# so this scratch image honours the same fixed non-root USER as the .NET images.
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/ese_dump"]
LABEL org.opencontainers.image.title="get-sybers/esedump" \
      org.opencontainers.image.description="Linux-native ESE database dumper (static Go, go-ese): parses SRUM (SRUDB.dat) with IdMap/SID enrichment and SUM (Current.mdb) databases that SrumECmd/SumECmd refuse off-Windows. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="ese_dump" \
      com.get-sybers.eztool.substitute-for="SrumECmd,SumECmd" \
      com.get-sybers.hardened="true"
