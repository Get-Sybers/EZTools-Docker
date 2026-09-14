# syntax=docker/dockerfile:1
#
# gole — Linux-native Windows Shortcut (.lnk) parser, a static-Go substitute for
# Eric Zimmerman's LECmd (.NET) for the DX_DFIR pipeline.
#
# LECmd runs under the .NET runtime; this image replaces it with a single static
# Go binary (on parsiya/golnk) that parses Shell Link (.lnk) files and emits the
# same facts LECmd's operator/CSV lane reads — target Created/Modified/Accessed,
# TargetFileSize, LocalPath, RelativePath, WorkingDirectory, Arguments,
# IconLocation, plus the decoded header/file-attribute flag sets — as JSONL or
# CSV. Same get-sybers/<tool> tag and -f/-d + --json/--csv CLI the zimmerman lane
# already calls, so the pipeline keeps docker-running it unchanged; only the .NET
# runtime is gone. See gole/main.go for the LECmd field mapping.
#
# The final image is FROM scratch: one static binary, nothing else. The hardening
# contract is met by construction — no shell, no python, no package manager, no
# setuid, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/gole:latest -f gole/Dockerfile gole
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/gole:latest -d /input --csv /output --csvf lecmd.csv

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gole .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args. Any other outcome fails the build here rather than shipping a broken bin.
RUN /gole 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /gole /gole
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/gole"]
LABEL org.opencontainers.image.title="get-sybers/gole" \
      org.opencontainers.image.description="Linux-native Windows Shortcut (.lnk) parser (static Go): parses Shell Link files to CSV/JSONL (target times, LocalPath, RelativePath, WorkingDir, Arguments, flag sets) — a .NET-free substitute for LECmd. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="gole" \
      com.get-sybers.eztool.substitute-for="LECmd" \
      com.get-sybers.hardened="true"
