# syntax=docker/dockerfile:1
#
# goappcompat — Linux-native Windows AppCompatCache (ShimCache) parser, a
# static-Go substitute for Eric Zimmerman's AppCompatCacheParser (.NET) for the
# DX_DFIR pipeline.
#
# AppCompatCacheParser runs under the .NET runtime; this image replaces it with a
# single static Go binary on Velociraptor's regparser (+ its appcompatcache
# subpackage) that reads the AppCompatCache value from a SYSTEM hive and emits
# one record per shimcache entry (ControlSet, CacheEntryPosition, Path,
# LastModifiedTimeUTC, SourceFile) as CSV or JSONL. Same get-sybers/<tool> tag
# and CLI as the other GoDFIR tools; the zimmerman lane calls
# `-f /in/SYSTEM --csv /out --csvf appcompatcache.csv`.
#
# The final image is FROM scratch: one static binary, nothing else — no shell,
# no python, no package manager, no setuid, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/goappcompat:latest -f goappcompat/Dockerfile goappcompat
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/goappcompat:latest -f /input/SYSTEM --csv /output --csvf appcompatcache.csv

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goappcompat .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args — a panic/crash/unexpected exit fails the build here.
RUN /goappcompat 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /goappcompat /goappcompat
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
# Single run-as uid/gid, passed by the DX_DFIR image role (dxdfir_runtime_uid/gid)
# so this scratch image honours the same fixed non-root USER as the .NET images.
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/goappcompat"]
LABEL org.opencontainers.image.title="get-sybers/goappcompat" \
      org.opencontainers.image.description="Linux-native Windows AppCompatCache (ShimCache) parser (static Go, regparser): reads the AppCompatCache value from a SYSTEM hive to CSV/JSONL (ControlSet, position, path, last-modified) — a .NET-free substitute for AppCompatCacheParser. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.source="https://github.com/Velocidex/regparser" \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="goappcompat" \
      com.get-sybers.eztool.substitute-for="AppCompatCacheParser" \
      com.get-sybers.hardened="true"
