# syntax=docker/dockerfile:1
#
# All-in-one Eric Zimmerman tool image for the DX_DFIR pipeline — every
# Linux-viable EZ tool in ONE hardened image, selected at RUN time by a static
# Go launcher. Hardening stays at build time (the image is immutable and runs
# read-only; "hardening itself at runtime" is not a thing a root-less,
# shell-less container can do) — what the launcher restricts at runtime is
# WHICH parser executes: the first argument picks the tool, everything else is
# passed through, and nothing else in the image is reachable via the
# entrypoint.
#
#   docker build -t dfir/eztools:latest -f eztools-all/Dockerfile .
#
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --network none --read-only --tmpfs /tmp \
#     -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     dfir/eztools:latest EvtxECmd -f /input/Security.evtx --csv /output
#
#   docker run --rm dfir/eztools:latest list
#
# WxTCmd needs a writable, exec-capable /tmp (its SQLite interop unpacks a
# native library beside the DLL; the launcher copies the tool there first):
#   --tmpfs /tmp:rw,nosuid,nodev,exec,uid=2000,gid=2000,size=256m
#
# The tool set is the net9 CLI family that actually parses on Linux. PECmd,
# SrumECmd, SumECmd and VSCMount are deliberately ABSENT: they cannot parse
# artifacts on any non-Windows host (Windows-native decompression / ESE / VSS
# dependencies — verified empirically and in upstream source). Their Linux
# substitutes are the prefetch/ and srum/ images in this repo.
#
# Release pinning: put "<sha256>  <Tool>.zip" lines into
# eztools-all/checksums.sha256 — any tool listed there is verified, tools not
# listed are fetched unpinned (same trust model as EZTOOL_SHA256 in
# eztool/Dockerfile).

ARG DOTNET_VERSION=9.0
ARG GO_VERSION=1.24
# Zip basenames on download.ericzimmermanstools.com/net9/ (casing matters for
# the URL; the DLL inside each zip is located case-insensitively).
ARG EZTOOLS="AmcacheParser AppCompatCacheParser bstrings EvtxECmd iisGeolocate JLECmd LECmd MFTECmd RBCmd RecentFileCacheParser RECmd rla SBECmd SQLECmd WxTCmd"
ARG EZTOOL_BASE_URL="https://download.ericzimmermanstools.com/net9"

# ---- fetch + unpack every release --------------------------------------------
FROM debian:trixie-slim AS fetch
ARG EZTOOLS
ARG EZTOOL_BASE_URL
COPY eztools-all/checksums.sha256 /tmp/checksums.sha256
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates unzip; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /opt/eztools; \
    for tool in ${EZTOOLS}; do \
        curl -fsSL -o "/tmp/${tool}.zip" "${EZTOOL_BASE_URL}/${tool}.zip"; \
        # optional per-tool pin: a "<sha256>  <tool>.zip" line in checksums.sha256
        pin="$(grep -iE "^[0-9a-f]{64}  ${tool}\.zip$" /tmp/checksums.sha256 || true)"; \
        if [ -n "${pin}" ]; then \
            ( cd /tmp && echo "${pin}" | sha256sum -c - ); \
        fi; \
        unzip -q "/tmp/${tool}.zip" -d "/tmp/unz-${tool}"; \
        # locate the DLL case-insensitively (zip layouts and casing vary:
        # EvtxECmd ships an EvtxeCmd/ dir, rla ships rla.dll, some zips are
        # flat) and keep that DLL's whole directory — data sets like RECmd's
        # BatchExamples/, EvtxECmd's Maps/ and SQLECmd's Maps/ ride along.
        dll="$(find "/tmp/unz-${tool}" -iname "${tool}.dll" -print -quit)"; \
        test -n "${dll}"; \
        src="$(dirname "${dll}")"; \
        base="$(basename "${dll}" .dll)"; \
        mkdir -p "/opt/eztools/${tool}"; \
        cp -a "${src}/." "/opt/eztools/${tool}/"; \
        rm -f "/opt/eztools/${tool}/${base}.exe"; \
        rm -rf "/tmp/${tool}.zip" "/tmp/unz-${tool}"; \
    done

# ---- static launcher ----------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS launcher
WORKDIR /src
COPY eztools-all/launcher/go.mod ./
COPY eztools-all/launcher/main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /eztool .

# ---- minimal hardened image ----------------------------------------------------
FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_VERSION} AS hardened
ARG DFIR_UID=2000
ARG DFIR_GID=2000
COPY --from=fetch /opt/eztools /opt/eztools
COPY --from=launcher /eztool /usr/local/bin/eztool
# Build-time smoke: every baked tool must start through the launcher and
# produce help output. Exit codes alone are useless here (some EZ tools exit
# non-zero on --help, and the Windows-only ones exit 0 while refusing), so
# the build FAILS on silence or on the known fatal/platform signatures —
# which also catches a Windows-only tool sneaking into the EZTOOLS list.
RUN set -eux; \
    for dir in /opt/eztools/*/; do \
        tool="$(basename "${dir}")"; \
        out="$(/usr/local/bin/eztool "${tool}" --help 2>&1 || true)"; \
        if [ -z "${out}" ]; then \
            echo "SMOKE FAILED: ${tool} produced no output" >&2; exit 1; \
        fi; \
        if printf '%s' "${out}" | grep -Eiq \
            'You must install or update \.NET|No frameworks were found|Unhandled exception|A fatal error occurred|Non-Windows platforms not supported'; then \
            echo "SMOKE FAILED: ${tool}:" >&2; printf '%s\n' "${out}" | head -5 >&2; exit 1; \
        fi; \
    done
COPY hardening/harden.yml /tmp/hardening/harden.yml
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ansible-core; \
    ansible-playbook -c local -i localhost, /tmp/hardening/harden.yml \
        -e "harden_uid=${DFIR_UID}" -e "harden_gid=${DFIR_GID}"; \
    rm -rf /usr/bin/ansible* /usr/lib/python3/dist-packages/ansible* \
           /etc/ansible /root/.ansible /tmp/hardening \
           /usr/bin/python3* /usr/lib/python3* \
           /bin/sh /bin/dash /bin/bash /bin/rbash /usr/bin/sh /usr/bin/dash /usr/bin/bash /usr/bin/rbash

FROM scratch
COPY --from=hardened / /
ARG EZTOOLS
ARG EZTOOL_BASE_URL
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp DOTNET_CLI_HOME=/tmp \
    DOTNET_RUNNING_IN_CONTAINER=true DOTNET_EnableDiagnostics=0 \
    DOTNET_NOLOGO=1
WORKDIR /opt/eztools
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/usr/local/bin/eztool"]
LABEL org.opencontainers.image.title="dfir/eztools" \
      org.opencontainers.image.description="All-in-one minimal hardened Eric Zimmerman tool image (.NET) for the DX_DFIR pipeline: every Linux-viable EZ CLI tool behind a static Go launcher (first arg selects the tool). uid0 renamed+locked, no ansible/apt/pip/sudo/setuid, no shell, no python, runs as uid 2000." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="all" \
      com.get-sybers.eztool.set="${EZTOOLS}" \
      com.get-sybers.eztool.url="${EZTOOL_BASE_URL}" \
      com.get-sybers.hardened="true"
