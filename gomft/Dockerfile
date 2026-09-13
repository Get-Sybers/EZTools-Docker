# syntax=docker/dockerfile:1
#
# gomft — Linux-native Windows $MFT parser, a static-Go substitute for Eric
# Zimmerman's MFTECmd ($MFT mode) for the DX_DFIR pipeline.
#
# MFTECmd runs under the .NET runtime; this image replaces it with a single
# static Go binary on Velociraptor's go-ntfs that parses a raw $MFT and emits
# one record per entry (entry/sequence, parent ref, name+extension, size, the
# $SI/$FN MACB timestamps, flags, ADS) as JSONL or CSV. Same get-sybers/<tool>
# pattern and CLI as the other GoDFIR tools; `-d` finds the $MFT by its "FILE"
# signature, so Plaso's image_export rename ($MFT -> _MFT) parses too.
#
# The final image is FROM scratch: one static binary, nothing else — no shell,
# no python, no package manager, no setuid, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/gomft:latest -f gomft/Dockerfile gomft
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/gomft:latest -d /input --json /output --jsonf mftecmd.json

# go-ntfs's module graph requires go >= 1.25; the official images pin
# GOTOOLCHAIN=local, so the builder must itself be >= 1.25.
ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gomft .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args — a panic/crash/unexpected exit fails the build here.
RUN /gomft 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /gomft /gomft
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
# Single run-as uid/gid, passed by the DX_DFIR image role (dxdfir_runtime_uid/gid)
# so this scratch image honours the same fixed non-root USER as the .NET images.
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/gomft"]
LABEL org.opencontainers.image.title="get-sybers/gomft" \
      org.opencontainers.image.description="Linux-native Windows \$MFT parser (static Go, go-ntfs): parses a raw \$MFT to JSONL/CSV (entry/parent refs, name, size, \$SI/\$FN MACB timestamps, flags, ADS) — a .NET-free substitute for MFTECmd. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.source="https://github.com/Velocidex/go-ntfs" \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="gomft" \
      com.get-sybers.eztool.substitute-for="MFTECmd" \
      com.get-sybers.hardened="true"
