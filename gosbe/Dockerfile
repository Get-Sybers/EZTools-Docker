# syntax=docker/dockerfile:1
#
# gosbe — Linux-native Windows ShellBags parser, a static-Go substitute for
# Eric Zimmerman's SBECmd for the DX_DFIR pipeline.
#
# SBECmd runs under the .NET runtime and walks the BagMRU shellbag tree in
# NTUSER.DAT / UsrClass.dat. This image replaces it with a single static Go
# binary on Velociraptor's regparser: it walks each BagMRU root, decodes the
# shell items (0x1F GUID folders -> known-folder names, 0x2F volumes, 0x30-0x3F
# file/dir entries -> the BEEF0004 Unicode long name or the ANSI short name),
# reconstructs each shellbag's AbsolutePath, and emits one record per shellbag
# (BagPath, Slot, NodeSlot, MRUPosition, ShellType, Value, AbsolutePath,
# LastWriteTime) as JSONL. Shell-item types it does not decode are emitted with
# their ShellType only — never an invented path.
#
# Dirty-hive .LOG1/.LOG2 replay (see main.go): recovers the logs into a copy
# written under --work-dir. That dir must be WRITABLE — the rootfs is read-only,
# so mount a tmpfs and point --work-dir at it. Without a writable work dir,
# replay falls back to the committed hive (a stderr note).
#
# The final image is FROM scratch: one static binary, nothing else — no shell,
# no python, no package manager, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/gosbe:latest -f gosbe/Dockerfile gosbe
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
#     --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
#     -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/gosbe:latest -d /input --json /output --jsonf SBECmd_Output.json --work-dir /work

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gosbe .
# Sanity-gate the build: no args -> usage -> exit 1 (a panic/crash fails here).
RUN /gosbe 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /gosbe /gosbe
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/gosbe"]
LABEL org.opencontainers.image.title="get-sybers/gosbe" \
      org.opencontainers.image.description="Linux-native Windows ShellBags parser (static Go, regparser): walks the BagMRU tree in NTUSER.DAT/UsrClass.dat, decodes shell items (GUID folders, volumes, file/dir BEEF0004 long names), reconstructs AbsolutePath, emits one record per shellbag (BagPath, Slot, NodeSlot, ShellType, Value, AbsolutePath, LastWriteTime) as JSONL — a .NET-free substitute for SBECmd. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.source="https://github.com/Velocidex/regparser" \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="gosbe" \
      com.get-sybers.eztool.substitute-for="SBECmd" \
      com.get-sybers.hardened="true"
