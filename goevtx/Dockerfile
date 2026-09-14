# syntax=docker/dockerfile:1
#
# goevtx — Linux-native Windows Event Log (.evtx) parser, a static-Go substitute
# for Eric Zimmerman's EvtxECmd for the DX_DFIR pipeline.
#
# EvtxECmd runs under the .NET runtime; this image replaces it with a single
# static Go binary on Velociraptor's go-evtx that parses .evtx and emits the
# EvtxECmd *.json shape the evtx lane + byakugan's winevt/evtx maps consume
# (EventId, Provider, Channel, Computer, EventRecordId, TimeCreated, UserId,
# Payload={"EventData":{"Data":[{@Name,#text}...]}}, SourceFile, MapDescription).
# It does NOT reproduce EvtxECmd's Maps layer (PayloadData/MapDescription) —
# byakugan reads the raw EventData, not those derived columns.
#
# The final image is FROM scratch: one static binary, nothing else — no shell,
# no python, no package manager, no setuid, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/goevtx:latest -f goevtx/Dockerfile goevtx
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/goevtx:latest -f /input/Security.evtx --json /output \
#     --jsonf Security_EvtxECmd_Output.json --xml /output --xmlf Security_EvtxECmd_Output.xml

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /goevtx .
# Sanity-gate the build: the binary must run and exit 1 (its usage code) with no
# args — a panic/crash/unexpected exit fails the build here.
RUN /goevtx 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /goevtx /goevtx
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/goevtx"]
LABEL org.opencontainers.image.title="get-sybers/goevtx" \
      org.opencontainers.image.description="Linux-native Windows Event Log (.evtx) parser (static Go, go-evtx): emits the EvtxECmd JSON shape (EventId/Channel/Computer/Provider/EventRecordId/TimeCreated + Payload EventData.Data[@Name/#text]) — a .NET-free substitute for EvtxECmd. FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.source="https://github.com/Velocidex/evtx" \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="goevtx" \
      com.get-sybers.eztool.substitute-for="EvtxECmd" \
      com.get-sybers.hardened="true"
