# syntax=docker/dockerfile:1
#
# Parameterized Eric Zimmerman tool image for the DX_DFIR pipeline — the SAME
# recipe as docker/evtxecmd (fetch the published .NET release at build time,
# bake into a minimal-hardened .NET runtime, tool as the pinned ENTRYPOINT),
# generalized over the tool name so every EZ tool builds identically:
#
#   docker build -t dfir/recmd:latest --build-arg EZTOOL=RECmd \
#     -f docker/eztool/Dockerfile docker
#   docker build -t dfir/srumecmd:latest --build-arg EZTOOL=SrumECmd \
#     -f docker/eztool/Dockerfile docker
#
# Pin the release (recommended):
#   --build-arg EZTOOL_SHA256=<sha256 of <EZTOOL>.zip>
#
# The whole release directory is kept — tools that ship data sets alongside the
# DLL (RECmd's BatchExamples/, SQLECmd's Maps/) keep them at
# /opt/eztool/<that dir>, reachable from the caller's flags. The .exe stub is
# dropped (the DLL is the entrypoint). EZ tools are MIT-licensed; this fetches
# the published release at build time — a recipe, not a committed binary.
#
# Run (the caller supplies only the flags — the DLL is the entrypoint):
#   docker run --rm -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
#     dfir/recmd:latest -d /input --bn /opt/eztool/BatchExamples/... --csv /output

ARG DOTNET_VERSION=9.0
ARG EZTOOL=EvtxECmd
ARG EZTOOL_URL=""
ARG DFIR_UID=2000
ARG DFIR_GID=2000

# ---- fetch + unpack the published release -----------------------------------
FROM debian:trixie-slim AS fetch
ARG EZTOOL
ARG EZTOOL_URL
ARG EZTOOL_SHA256=""
ARG EZTOOL_ALLOW_WINDOWS_ONLY=""
RUN set -eux; \
    # Fail FAST on the four tools that cannot parse on Linux (all verified
    # empirically against real artifacts AND in upstream source): PECmd's
    # startup guard exits on any non-Windows platform (Prefetch P/Invokes
    # ntdll!RtlDecompressBufferEx); SrumECmd and SumECmd read ESE through
    # ManagedEsent (P/Invokes Windows' esent.dll); VSCMount symlinks the
    # Windows VSS device namespace. All four print their refusal and exit 0,
    # so a built image would LOOK healthy while producing nothing. Linux
    # substitutes: prefetch/ (PECmd), srum/ (SrumECmd, SumECmd); VSS access on
    # Linux is libvshadow on the host. Set EZTOOL_ALLOW_WINDOWS_ONLY=1 to
    # build anyway (e.g. just to extract a release).
    tool_lc="$(printf '%s' "${EZTOOL}" | tr '[:upper:]' '[:lower:]')"; \
    case "${tool_lc}" in \
        pecmd|srumecmd|sumecmd|vscmount) \
            if [ "${EZTOOL_ALLOW_WINDOWS_ONLY}" != "1" ]; then \
                echo "ERROR: ${EZTOOL} cannot parse artifacts on Linux (Windows-native" >&2; \
                echo "dependency). Use the prefetch/ or srum/ image instead, or set" >&2; \
                echo "--build-arg EZTOOL_ALLOW_WINDOWS_ONLY=1 to build it anyway." >&2; \
                exit 1; \
            fi ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates unzip; \
    rm -rf /var/lib/apt/lists/*; \
    url="${EZTOOL_URL:-https://download.ericzimmermanstools.com/net9/${EZTOOL}.zip}"; \
    curl -fsSL -o /tmp/tool.zip "${url}"; \
    if [ -n "${EZTOOL_SHA256}" ]; then \
        echo "${EZTOOL_SHA256}  /tmp/tool.zip" | sha256sum -c -; \
    fi; \
    unzip -q /tmp/tool.zip -d /tmp/unz; \
    # -iname: release zip casing varies (EvtxECmd ships an EvtxeCmd/ dir, rla
    # ships rla.dll) — locate the DLL case-insensitively and use ITS real
    # basename for the runtimeconfig/deps trio.
    dll="$(find /tmp/unz -iname "${EZTOOL}.dll" -print -quit)"; \
    test -n "${dll}"; \
    src="$(dirname "${dll}")"; \
    base="$(basename "${dll}" .dll)"; \
    mkdir -p /opt/eztool; \
    cp -a "${src}/." /opt/eztool/; \
    test -f "/opt/eztool/${base}.dll"; \
    rm -f "/opt/eztool/${base}.exe"; \
    # Fixed-path entrypoint: `dotnet tool.dll` resolves tool.runtimeconfig.json
    # and tool.deps.json by the GIVEN name, so the whole trio is linked under
    # the stable name (the deps content references the real assembly, which the
    # runtime probes in the same dir).
    ln -s "/opt/eztool/${base}.dll" /opt/eztool/tool.dll; \
    for suffix in runtimeconfig.json deps.json; do \
        if [ -f "/opt/eztool/${base}.${suffix}" ]; then \
            ln -s "/opt/eztool/${base}.${suffix}" "/opt/eztool/tool.${suffix}"; \
        fi; \
    done

# ---- minimal hardened image --------------------------------------------------
FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_VERSION} AS hardened
ARG EZTOOL
ARG DFIR_UID
ARG DFIR_GID
COPY --from=fetch /opt/eztool /opt/eztool
RUN dotnet /opt/eztool/tool.dll --help > /dev/null || true
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
ARG EZTOOL
ARG EZTOOL_URL
ARG DFIR_UID
ARG DFIR_GID
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp DOTNET_CLI_HOME=/tmp \
    DOTNET_RUNNING_IN_CONTAINER=true DOTNET_EnableDiagnostics=0 \
    DOTNET_NOLOGO=1
WORKDIR /opt/eztool
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["dotnet", "/opt/eztool/tool.dll"]
LABEL org.opencontainers.image.title="dfir/eztool" \
      org.opencontainers.image.description="Minimal hardened Eric Zimmerman tool (.NET) for the DX_DFIR pipeline: uid0 renamed+locked, no ansible/apt/pip/sudo/setuid, no shell, no python, runs as uid 2000. Parameterized over EZTOOL." \
      org.opencontainers.image.licenses="MIT" \
      com.get-sybers.eztool="${EZTOOL}" \
      com.get-sybers.eztool.url="${EZTOOL_URL}" \
      com.get-sybers.hardened="true"
