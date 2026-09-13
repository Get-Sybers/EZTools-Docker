# syntax=docker/dockerfile:1
#
# gorb — Linux-native Windows Recycle Bin ($I) parser, a static-Go substitute
# for Eric Zimmerman's RBCmd (.NET) for the DX_DFIR pipeline.
#
# RBCmd runs under the .NET runtime; this image replaces it with a single static
# Go binary that parses the modern $I metadata records (v1 Vista–8.0 and v2
# Win8.1/10/11) and emits the same facts (SourceName, FileType, FileName,
# FileSize, DeletedOn) as CSV or JSONL. Same get-sybers/<tool> tag, same CLI
# contract the zimmerman lane already calls (`-d /in --csv /out --csvf rbcmd.csv`),
# so the pipeline keeps docker-running it unchanged — only the .NET runtime is
# gone. See rbcmd/main.go for the $I layout notes and the RBCmd field mapping.
#
# The final image is FROM scratch: one static binary, nothing else. The
# hardening contract is met by construction — no shell, no python, no package
# manager, no setuid, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/gorb:latest -f gorb/Dockerfile gorb
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/gorb:latest -d /input --csv /output --csvf rbcmd.csv

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gorb .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args. Any other outcome — a panic, a crash, or an unexpected 0/2 — fails the
# build here rather than shipping a broken binary.
RUN /gorb 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /gorb /gorb
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
# Single run-as uid/gid, passed by the DX_DFIR image role (dxdfir_runtime_uid/gid)
# so this scratch image honours the same fixed non-root USER as the .NET images.
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/gorb"]
LABEL org.opencontainers.image.title="get-sybers/gorb" \
      org.opencontainers.image.description="Linux-native Windows Recycle Bin (\$I) parser (static Go): parses v1 (Vista–8.0) and v2 (Win8.1/10/11) \$I metadata records to CSV/JSONL — a .NET-free substitute for RBCmd. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="gorb" \
      com.get-sybers.eztool.substitute-for="RBCmd" \
      com.get-sybers.hardened="true"
