#!/usr/bin/env bash
#
# Build the hardened DFIR images: one per-tool image per Linux-viable EZ tool
# still on .NET (eztool/Dockerfile), the GoDFIR Go tools (goprefetch/, goese/,
# gorb/), and — on request — the all-in-one image (eztools-all/).
#
#   ./build-all.sh                 # every .NET per-tool image + the Go tools
#   ./build-all.sh recmd mftecmd   # a subset (names case-insensitive)
#   ./build-all.sh all-in-one      # the single get-sybers/eztools image
#   ./build-all.sh goprefetch goese gorb
#
# PECmd, SrumECmd, SumECmd and VSCMount cannot parse artifacts on Linux (see
# README): goprefetch and goese are their Go substitutes. gorb replaces RBCmd
# (Linux-viable under .NET) with a static Go binary to drop the .NET runtime.
# As each remaining .NET tool is ported to Go it gets a go-name too (RECmd ->
# gore, ...) — DX_DFIR #188 initiative 2. Ported so far: MFTECmd -> gomft
# (go-ntfs), EvtxECmd -> goevtx (go-evtx), Amcache/AppCompatCache ->
# goamcache/goappcompat (regparser), LECmd -> gole (golnk), JLECmd -> gojle
# (mscfb), plus gorb/goprefetch/goese.
set -Eeuo pipefail
cd "$(dirname "$0")"

# Zip basenames on download.ericzimmermanstools.com/net9/ — casing matters for
# the download URL, so keep these exactly as published.
LINUX_TOOLS=(
  bstrings iisGeolocate
  RecentFileCacheParser RECmd rla SBECmd SQLECmd WxTCmd
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

build_goamcache() {
  echo "==> get-sybers/goamcache (Go, AmcacheParser substitute)"
  docker build -t get-sybers/goamcache:latest -f goamcache/Dockerfile goamcache
}

build_goappcompat() {
  echo "==> get-sybers/goappcompat (Go, AppCompatCacheParser substitute)"
  docker build -t get-sybers/goappcompat:latest -f goappcompat/Dockerfile goappcompat
}

build_goevtx() {
  echo "==> get-sybers/goevtx (Go, EvtxECmd substitute)"
  docker build -t get-sybers/goevtx:latest -f goevtx/Dockerfile goevtx
}

build_gole() {
  echo "==> get-sybers/gole (Go, LECmd substitute)"
  docker build -t get-sybers/gole:latest -f gole/Dockerfile gole
}

build_gojle() {
  echo "==> get-sybers/gojle (Go, JLECmd substitute)"
  docker build -t get-sybers/gojle:latest -f gojle/Dockerfile gojle
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
    goamcache|amcacheparser) build_goamcache; return ;;
    goappcompat|appcompatcacheparser) build_goappcompat; return ;;
    goevtx|evtxecmd) build_goevtx; return ;;
    gole|lecmd) build_gole; return ;;
    gojle|jlecmd) build_gojle; return ;;
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
  echo "unknown tool '$1' — valid: ${LINUX_TOOLS[*]} goprefetch goese gorb gomft goamcache goappcompat goevtx gole gojle all-in-one" >&2
  echo "  (the substituted EZ-tool names also work: pecmd, srumecmd/sumecmd, rbcmd, mftecmd, amcacheparser, appcompatcacheparser, evtxecmd, lecmd, jlecmd)" >&2
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
  build_goamcache
  build_goappcompat
  build_goevtx
  build_gole
  build_gojle
fi
echo "done."
