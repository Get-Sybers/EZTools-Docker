# syntax=docker/dockerfile:1
#
# gojle — Linux-native Windows Jump List parser, a static-Go substitute for Eric
# Zimmerman's JLECmd (.NET) for the DX_DFIR pipeline.
#
# JLECmd runs under the .NET runtime; this image replaces it with a single static
# Go binary that parses AutomaticDestinations (*.automaticDestinations-ms — an OLE
# compound file, via richardlehane/mscfb) and their DestList stream, and emits the
# AutomaticDestinations record shape byakugan's jlecmd_dest map / jlecmd adapter
# consume: one record per jump-list file, each with the per-target DestListEntries
# (Path, EntryNumber, CreatedOn, LastModified, Hostname, InteractionCount,
# MRUPosition, Pinned, MacAddress, VolumeDroid). CreatedOn is recovered from each
# entry's embedded LNK stream; the MAC comes from the FileDroid GUID node. Same
# get-sybers/<tool> tag and -f/-d + --json CLI the zimmerman lane calls, so the
# pipeline keeps docker-running it unchanged; only the .NET runtime is gone.
# See gojle/main.go for the DestList layout notes and the JLECmd field mapping.
#
# The final image is FROM scratch: one static binary, nothing else. The hardening
# contract is met by construction — no shell, no python, no package manager, no
# setuid, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/gojle:latest -f gojle/Dockerfile gojle
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/gojle:latest -d /input --json /output --jsonf jlecmd.json

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gojle .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args. Any other outcome fails the build here rather than shipping a broken bin.
RUN /gojle 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /gojle /gojle
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/gojle"]
LABEL org.opencontainers.image.title="get-sybers/gojle" \
      org.opencontainers.image.description="Linux-native Windows Jump List parser (static Go): parses AutomaticDestinations OLE + DestList to the JLECmd AutomaticDestinations JSON shape byakugan consumes — a .NET-free substitute for JLECmd. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="gojle" \
      com.get-sybers.eztool.substitute-for="JLECmd" \
      com.get-sybers.hardened="true"
