#!/usr/bin/env bash
#
# Build the hardened DFIR images: one per-tool image per Linux-viable EZ tool
# still on .NET (eztool/Dockerfile), the GoDFIR Go tools (goprefetch/, goese/,
# gorb/), and — on request — the all-in-one image (eztools-all/).
#
#   ./build-all.sh                 # every .NET per-tool image + goprefetch + goese + gorb + gomft
#   ./build-all.sh recmd mftecmd   # a subset (names case-insensitive)
#   ./build-all.sh all-in-one      # the single get-sybers/eztools image
#   ./build-all.sh goprefetch goese gorb
#
# PECmd, SrumECmd, SumECmd and VSCMount cannot parse artifacts on Linux (see
# README): goprefetch and goese are their Go substitutes. gorb replaces RBCmd
# (Linux-viable under .NET) with a static Go binary to drop the .NET runtime.
# As each remaining .NET tool is ported to Go it gets a go-name too (RECmd ->
# gore, EvtxECmd -> goevtx, ...) — DX_DFIR #188 initiative 2. MFTECmd is ported
# (gomft, on go-ntfs).
set -Eeuo pipefail
cd "$(dirname "$0")"

# Zip basenames on download.ericzimmermanstools.com/net9/ — casing matters for
# the download URL, so keep these exactly as published.
LINUX_TOOLS=(
  AmcacheParser AppCompatCacheParser bstrings EvtxECmd iisGeolocate JLECmd
  LECmd RecentFileCacheParser RECmd rla SBECmd SQLECmd WxTCmd
)

lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

build_eztool() {
  local tool="$1"
  echo "==> get-sybers/$(lc "${tool}") (eztool/Dockerfile, EZTOOL=${tool})"
  docker build -t "get-sybers/$(lc "${tool}"):latest" \
    --build-arg EZTOOL="${tool}" -f eztool/Dockerfile .
}

build_goprefetch() {
  echo "==> get-sybers/goprefetch (Go, PECmd substitute)"
  docker build -t get-sybers/goprefetch:latest -f goprefetch/Dockerfile goprefetch
}

build_goese() {
  echo "==> get-sybers/goese (Go, SrumECmd/SumECmd substitute)"
  docker build -t get-sybers/goese:latest -f goese/Dockerfile goese
}

build_gorb() {
  echo "==> get-sybers/gorb (Go, RBCmd substitute)"
  docker build -t get-sybers/gorb:latest -f gorb/Dockerfile gorb
}

build_gomft() {
  echo "==> get-sybers/gomft (Go, MFTECmd substitute)"
  docker build -t get-sybers/gomft:latest -f gomft/Dockerfile gomft
}

build_all_in_one() {
  echo "==> get-sybers/eztools (all-in-one, eztools-all/Dockerfile)"
  docker build -t get-sybers/eztools:latest -f eztools-all/Dockerfile .
}

resolve() {
  local want
  want="$(lc "$1")"
  case "${want}" in
    goprefetch|prefetch|pecmd) build_goprefetch; return ;;
    goese|esedump|srum|srumecmd|sumecmd) build_goese; return ;;
    gorb|rbcmd) build_gorb; return ;;
    gomft|mftecmd) build_gomft; return ;;
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
  echo "unknown tool '$1' — valid: ${LINUX_TOOLS[*]} goprefetch goese gorb gomft all-in-one" >&2
  exit 1
}

if [ "$#" -gt 0 ]; then
  for arg in "$@"; do resolve "${arg}"; done
else
  for tool in "${LINUX_TOOLS[@]}"; do build_eztool "${tool}"; done
  build_goprefetch
  build_goese
  build_gorb
  build_gomft
fi
echo "done."
