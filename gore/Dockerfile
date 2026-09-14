# syntax=docker/dockerfile:1
#
# gore — Linux-native Windows Registry batch parser, a static-Go substitute for
# Eric Zimmerman's RECmd for the DX_DFIR pipeline.
#
# RECmd runs under the .NET runtime and applies a batch (.reb) of keys/values
# across a set of hives. This image replaces it with a single static Go binary on
# Velociraptor's regparser: it reads a batch file, walks each requested key in
# each hive under -d (content-detected regf; HiveType from the file name), and
# emits one record per value (HivePath, HiveType, Category, KeyPath, ValueName,
# ValueType, ValueData, LastWriteTimestamp, …) as JSONL or CSV — the same shape
# byakugan's recmd_batch map consumes.
#
# The bundled /batch/default.reb is a CURATED forensic-key set (persistence /
# execution / config), NOT Eric Zimmerman's Kroll_Batch.reb (which is not
# redistributable here). Supply your own with --bn /path/to/batch.reb.
#
# Dirty-hive .LOG1/.LOG2 replay (see main.go): when the logs sit beside a hive it
# recovers them into a copy written under --work-dir. That dir must be WRITABLE —
# the rootfs is read-only, so mount a tmpfs and point --work-dir at it. Without a
# writable work dir, replay falls back to the committed hive (a stderr note).
#
# The final image is FROM scratch: one static binary + the batch file, nothing
# else — no shell, no python, no package manager, no libc; runs as uid 2000.
#
#   docker build -t get-sybers/gore:latest -f gore/Dockerfile gore
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
#     --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
#     -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     get-sybers/gore:latest -d /input --json /output --jsonf RECmd_Batch_Output.json --work-dir /work

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gore .
# Sanity-gate the build: no args -> usage -> exit 1 (a panic/crash fails here).
RUN /gore 2>/dev/null; [ $? -eq 1 ]

FROM scratch
COPY --from=build /gore /gore
COPY batch/ /batch/
COPY <<EOF /etc/dfir-hardened
user=dfir uid=2000
static_binary=true
EOF
ARG DFIR_UID=2000
ARG DFIR_GID=2000
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/gore"]
LABEL org.opencontainers.image.title="get-sybers/gore" \
      org.opencontainers.image.description="Linux-native Windows Registry batch parser (static Go, regparser): applies a .reb batch across hives and emits one record per value (HivePath, HiveType, Category, KeyPath, ValueName, ValueType, ValueData, LastWriteTimestamp) as JSONL/CSV for byakugan recmd_batch — a .NET-free substitute for RECmd. Bundles a curated default.reb (NOT Kroll_Batch.reb). FROM scratch: no shell, no python, no libc, runs as uid 2000." \
      org.opencontainers.image.source="https://github.com/Velocidex/regparser" \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="gore" \
      com.get-sybers.eztool.substitute-for="RECmd" \
      com.get-sybers.hardened="true"
