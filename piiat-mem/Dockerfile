# syntax=docker/dockerfile:1
#
# get-sybers/piiat-mem — the PIIAT-Mem memory-forensics tool in ONE hardened
# image. PIIAT-Mem drives Volatility 3 (which IS python, irreducibly) over a
# memory image and renders flat per-plugin JSONL for the DX_DFIR CAR lane.
#
# It used to run as `python -m piiat_mem` ON THE HOST, and piiat_mem then did its
# OWN `docker run` of a Volatility image — two layers, host execution, and a
# vendored submodule DX_DFIR had to carry. This image fuses both: piiat_mem +
# Volatility 3 + the jsonl_dfir renderer + the piiat plugins, run with
# piiat_mem's `--native` backend so Volatility runs IN-PROCESS — confined here,
# with no nested docker.
#
# The engine SOURCE TREE is cloned at build time at the pinned commit (no
# vendored checkout in DX_DFIR); it is run from the tree via PYTHONPATH because
# the renderer (jsonl_dfir_renderer.py) and plugins/ live at the repo root, not
# inside the piiat_mem package.
#
#   docker build -t get-sybers/piiat-mem:latest \
#     --build-arg PIIAT_MEM_REF=<40-hex sha> -f piiat-mem/Dockerfile .
#
# The caller supplies piiat_mem's flags (the image forces --native); e.g. the
# DX_DFIR volatility lane mounts the image read-only, an output dir read-write
# and an ISF symbol cache, then:
#   docker run --rm --network none --read-only --tmpfs /tmp \
#     -v "$mem_dir:/mem:ro" -v "$out:/out" -v "$symbols:/symbols" \
#     get-sybers/piiat-mem:latest -f /mem/<image> -o /out --symbols /symbols
# /out and /symbols must be writable by the runtime uid (2000); /tmp is HOME and
# Volatility's cache, so a --read-only rootfs needs the tmpfs. Windows plugins
# fetch ISF symbols on first use: under --native piiat_mem's --symbols-online is
# a no-op (it only lifts ITS OWN container's isolation), so either pre-seed
# /symbols or give THIS container network for that run.
ARG BASE=python:3.12-slim
ARG PIIAT_MEM_REPO=https://github.com/Get-Sybers/PIIAT-Mem
ARG PIIAT_MEM_REF=main
ARG VOLATILITY_VERSION=2.28.0
ARG YARA_PYTHON_VERSION=4.5.4
ARG DFIR_UID=2000
ARG DFIR_GID=2000

# --- stage 1: fetch the pinned PIIAT-Mem source ------------------------------
# Cloned, not vendored: the pin is authoritative in DX_DFIR's sources.yml, passed
# as --build-arg PIIAT_MEM_REF. The .git dirs are dropped — only the package,
# renderer and plugins ship.
FROM debian:trixie-slim AS src
ARG PIIAT_MEM_REPO
ARG PIIAT_MEM_REF
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates; \
    rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    git clone "${PIIAT_MEM_REPO}" /src; \
    git -C /src checkout "${PIIAT_MEM_REF}"; \
    find /src -name .git -prune -exec rm -rf {} +

# --- stage 2: python runtime + Volatility + in-image hardening ---------------
# Volatility IS python, so python is irreducible; pip/apt/ansible and every shell
# are removed by the shared build-time hardener. yara-python backs the
# windows.vadyarascan plugin. Volatility's only hard dependency is pefile.
#
# The build-time hardener (ansible-core) is installed into a THROWAWAY dir
# (pip --target), not site-packages: removing that one dir afterwards drops
# ansible AND its whole dependency closure (jinja2, cryptography, cffi, PyYAML,
# resolvelib, …), so the runtime site-packages holds nothing but Volatility,
# yara-python and pefile.
FROM ${BASE} AS hardened
ARG VOLATILITY_VERSION
ARG YARA_PYTHON_VERSION
ARG DFIR_UID
ARG DFIR_GID
RUN set -eux; \
    pip install --no-cache-dir \
      "volatility3==${VOLATILITY_VERSION}" \
      "yara-python==${YARA_PYTHON_VERSION}"; \
    pip install --no-cache-dir --target /tmp/ansible ansible-core
# The PIIAT-Mem tree (piiat_mem package + jsonl_dfir_renderer.py + plugins/): run
# from here via PYTHONPATH so runner.py resolves the renderer and plugins, which
# live at the tree root (not inside the package).
COPY --from=src /src /opt/piiat-mem
COPY hardening/harden.yml /tmp/hardening/harden.yml
RUN set -eux; \
    # world-readable so the non-root runtime uid can import the tree.
    chmod -R a+rX /opt/piiat-mem; \
    PYTHONPATH=/tmp/ansible /tmp/ansible/bin/ansible-playbook -c local -i localhost, \
      /tmp/hardening/harden.yml \
      -e harden_uid=${DFIR_UID} -e harden_gid=${DFIR_GID}; \
    # remove the build-time hardener (+ its deps, one dir), every shell, and
    # perl (the base ships it; nothing here needs a second interpreter). KEEP
    # python3 + the baked tree (python is the tool, like plaso/byakugan).
    rm -rf /tmp/ansible /etc/ansible /root/.ansible /tmp/hardening \
           /bin/sh /bin/dash /bin/bash /bin/rbash \
           /usr/bin/sh /usr/bin/dash /usr/bin/bash /usr/bin/rbash \
           /usr/bin/bashbug /usr/bin/perl*

FROM scratch
COPY --from=hardened / /
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ARG PIIAT_MEM_REF
# HOME/XDG_CACHE_HOME=/tmp: the only writable path on the read-only rootfs.
# PYTHONPATH: run piiat_mem from its baked source tree.
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/piiat-mem
USER ${DFIR_UID}:${DFIR_GID}
# --native: Volatility runs IN-PROCESS, confined by this image (no nested docker).
ENTRYPOINT ["python3", "-m", "piiat_mem", "--native"]
LABEL org.opencontainers.image.title="get-sybers/piiat-mem" \
      org.opencontainers.image.description="Minimal hardened PIIAT-Mem (Volatility 3 memory forensics) for the DX_DFIR volatility lane: source cloned + built in at the sources.yml pin, uid0 renamed+locked, no ansible/apt/pip/sudo/setuid/shell, runs as a fixed non-root uid (default 2000). python kept (Volatility is python); runs Volatility in-process via --native, no nested docker." \
      com.get-sybers.hardened="true" \
      com.get-sybers.piiat-mem.ref="${PIIAT_MEM_REF}"
