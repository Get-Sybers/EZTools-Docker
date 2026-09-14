# syntax=docker/dockerfile:1
#
# goamcache — Linux-native Windows Amcache parser, a static-Go substitute for
# Eric Zimmerman's AmcacheParser for the DX_DFIR pipeline.
#
# AmcacheParser runs under the .NET runtime; this image replaces it with a single
# static Go binary on Velociraptor's regparser that parses an Amcache.hve and
# emits one record per program-execution file entry (key last-write time,
# ProgramId, SHA-1, full path, name, publisher/product/version, size) as CSV or
# JSONL. Same get-sybers/<tool> pattern and CLI as the other GoDFIR tools.
#
# Dirty-hive .LOG1/.LOG2 replay (see main.go): when the logs sit beside the hive
# it recovers them into a copy written under --work-dir. That dir must be
# WRITABLE — the rootfs is read-only, so mount a tmpfs and point --work-dir at it
# (the zimmerman lane adds `--tmpfs /work:...`, like wxtcmd). Without a writable
# work dir, replay just falls back to the committed hive (a stderr note).
#
# The final image is FROM scratch: one static binary, nothing else — no shell,
# no python, no package manager, no setuid, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/goamcache:latest -f goamcache/Dockerfile goamcache
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
#     --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
#     -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/goamcache:latest -f /input/Amcache.hve --csv /output --csvf amcache.csv -i --work-dir /work

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goamcache .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args — a panic/crash/unexpected exit fails the build here.
RUN /goamcache 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /goamcache /goamcache
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
# Single run-as uid/gid, passed by the DX_DFIR image role (dxdfir_runtime_uid/gid)
# so this scratch image honours the same fixed non-root USER as the .NET images.
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/goamcache"]
LABEL org.opencontainers.image.title="get-sybers/goamcache" \
      org.opencontainers.image.description="Linux-native Windows Amcache parser (static Go, regparser): parses Amcache.hve InventoryApplicationFile entries to CSV/JSONL (key time, ProgramId, SHA-1, path, name, size) — a .NET-free substitute for AmcacheParser. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.source="https://github.com/Velocidex/regparser" \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="goamcache" \
      com.get-sybers.eztool.substitute-for="AmcacheParser" \
      com.get-sybers.hardened="true"
