#!/usr/bin/env bash
#
# Build the hardened DFIR images: one per-tool image per Linux-viable EZ tool
# (eztool/Dockerfile), the Go substitute images (prefetch/, srum/, rbcmd/), and —
# on request — the all-in-one image (eztools-all/).
#
#   ./build-all.sh                 # every per-tool image + prefetch + esedump + rbcmd
#   ./build-all.sh recmd mftecmd   # a subset (names case-insensitive)
#   ./build-all.sh all-in-one      # the single get-sybers/eztools image
#   ./build-all.sh prefetch esedump rbcmd
#
# PECmd, SrumECmd, SumECmd and VSCMount are not in the list on purpose: they
# cannot parse artifacts on Linux (see README). prefetch and esedump are their
# Linux substitutes. RBCmd is Linux-viable under .NET but is ported to a static
# Go binary (rbcmd/) to drop the .NET runtime — the $I format is simple and
# fully specified (DX_DFIR #188 initiative 2).
set -Eeuo pipefail
cd "$(dirname "$0")"

# Zip basenames on download.ericzimmermanstools.com/net9/ — casing matters for
# the download URL, so keep these exactly as published.
LINUX_TOOLS=(
  AmcacheParser AppCompatCacheParser bstrings EvtxECmd iisGeolocate JLECmd
  LECmd MFTECmd RecentFileCacheParser RECmd rla SBECmd SQLECmd WxTCmd
)

lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

build_eztool() {
  local tool="$1"
  echo "==> get-sybers/$(lc "${tool}") (eztool/Dockerfile, EZTOOL=${tool})"
  docker build -t "get-sybers/$(lc "${tool}"):latest" \
    --build-arg EZTOOL="${tool}" -f eztool/Dockerfile .
}

build_prefetch() {
  echo "==> get-sybers/prefetch (Go, PECmd substitute)"
  docker build -t get-sybers/prefetch:latest -f prefetch/Dockerfile prefetch
}

build_esedump() {
  echo "==> get-sybers/esedump (Go, SrumECmd/SumECmd substitute)"
  docker build -t get-sybers/esedump:latest -f srum/Dockerfile srum
}

build_rbcmd() {
  echo "==> get-sybers/rbcmd (Go, RBCmd substitute)"
  docker build -t get-sybers/rbcmd:latest -f rbcmd/Dockerfile rbcmd
}

build_all_in_one() {
  echo "==> get-sybers/eztools (all-in-one, eztools-all/Dockerfile)"
  docker build -t get-sybers/eztools:latest -f eztools-all/Dockerfile .
}

resolve() {
  local want
  want="$(lc "$1")"
  case "${want}" in
    prefetch|pecmd) build_prefetch; return ;;
    esedump|srum|srumecmd|sumecmd) build_esedump; return ;;
    rbcmd) build_rbcmd; return ;;
    all-in-one|eztools|all) build_all_in_one; return ;;
    vscmount)
      echo "VSCMount manipulates the Windows VSS device namespace and has no" >&2
      echo "Linux container; use libvshadow (vshadowinfo/vshadowmount) on the host." >&2
      exit 1 ;;
  esac
  local tool
  for tool in "${LINUX_TOOLS[@]}"; do
    if [ "$(lc "${tool}")" = "${want}" ]; then
      build_eztool "${tool}"
      return
    fi
  done
  echo "unknown tool '$1' — valid: ${LINUX_TOOLS[*]} prefetch esedump rbcmd all-in-one" >&2
  exit 1
}

if [ "$#" -gt 0 ]; then
  for arg in "$@"; do resolve "${arg}"; done
else
  for tool in "${LINUX_TOOLS[@]}"; do build_eztool "${tool}"; done
  build_prefetch
  build_esedump
  build_rbcmd
fi
echo "done."
