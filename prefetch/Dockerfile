# syntax=docker/dockerfile:1
#
# prefetch_dump — Linux-native Windows Prefetch parser (PECmd's Linux
# substitute) for the DX_DFIR pipeline.
#
# PECmd is Windows-host-only (verified empirically, source and runtime: its
# guard exits "Non-Windows platforms not supported due to the need to load
# decompression specific Windows libraries!" with status 0 on ANY non-Windows
# platform, because the Prefetch library P/Invokes ntdll!RtlDecompressBufferEx
# for Win8+/Win10 MAM files). This image ships a static Go binary built on
# Velociraptor's go-prefetch, whose pure-Go LZXpress-Huffman fallback parses
# XP-era through Win11 prefetch — MAM compressed included — on Linux.
#
# The final image is FROM scratch: one static binary, nothing else. The
# hardening contract is met by construction — no shell, no python, no package
# manager, no setuid, no libc even; runs as uid 2000.
#
#   docker build -t dfir/prefetch:latest -f prefetch/Dockerfile prefetch
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     dfir/prefetch:latest -d /input --json /output
#
# Output: JSONL (or --csv) — SourceFilename, Executable, Path, Hash, Version,
# RunCount, LastRun, PreviousRuns, FilesAccessed. See prefetch/main.go for the
# PECmd field mapping notes.

# go-prefetch requires go >= 1.25 (module directive), and the official golang
# images set GOTOOLCHAIN=local, so the builder must be at least 1.25 itself.
ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /prefetch_dump . \
    && /prefetch_dump -f /dev/null 2>/dev/null || true

FROM scratch
COPY --from=build /prefetch_dump /prefetch_dump
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
USER 2000:2000
ENTRYPOINT ["/prefetch_dump"]
LABEL org.opencontainers.image.title="dfir/prefetch" \
      org.opencontainers.image.description="Linux-native Windows Prefetch parser (static Go, go-prefetch): parses XP through Win11 .pf including MAM/LZXpress-Huffman compressed files that PECmd refuses off-Windows. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="prefetch_dump" \
      com.get-sybers.eztool.substitute-for="PECmd" \
      com.get-sybers.hardened="true"
