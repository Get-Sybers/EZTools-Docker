# syntax=docker/dockerfile:1
#
# gowxt — Linux-native Windows Timeline (ActivitiesCache.db) parser, a static-Go
# substitute for Eric Zimmerman's WxTCmd for the DX_DFIR pipeline.
#
# WxTCmd runs under the .NET runtime; this image replaces it with a single static
# Go binary on modernc.org/sqlite (pure Go, no cgo) that reads the Windows
# Timeline SQLite DB and emits WxTCmd-style CSV/JSONL (Executable from AppId,
# DisplayText/ContentInfo from Payload, the Start/End/LastModified/Expiration
# timestamps, ActivityType). Same get-sybers/<tool> tag + CLI as the other
# GoDFIR tools.
#
# SQLite needs a writable working area; the rootfs is read-only and the input is
# mounted read-only, so gowxt copies the DB into --work-dir. Mount a tmpfs there:
#
#   docker build -t get-sybers/gowxt:latest -f gowxt/Dockerfile gowxt
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
#     --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
#     -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/gowxt:latest -f /input/ActivitiesCache.db --csv /output --work-dir /work
#
# The final image is FROM scratch: one static binary, nothing else — no shell,
# no python, no package manager, no setuid, no libc; runs as uid 2000.

ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gowxt .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args — a panic/crash/unexpected exit fails the build here.
RUN /gowxt 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /gowxt /gowxt
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/gowxt"]
LABEL org.opencontainers.image.title="get-sybers/gowxt" \
      org.opencontainers.image.description="Linux-native Windows Timeline (ActivitiesCache.db) parser (static Go, modernc sqlite): emits WxTCmd-style Activity CSV/JSONL — a .NET-free substitute for WxTCmd. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="gowxt" \
      com.get-sybers.eztool.substitute-for="WxTCmd" \
      com.get-sybers.hardened="true"
