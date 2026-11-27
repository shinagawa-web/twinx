#!/usr/bin/env bash
# Prints the tag of the measuring image: a digest of perf/Dockerfile and the files it
# copies, so that the image is built again only when one of them changes. perf/run.sh and
# .github/workflows/perf-image.yml both take it from here, so that they agree.
set -euo pipefail
cd "$(dirname "$0")"
files=(Dockerfile $(awk '$1 == "COPY" { for (i = 2; i < NF; i++) if ($i !~ /^--/) print $i }' Dockerfile))
for f in "${files[@]}"; do printf '%s\0' "$f"; cat "$f"; done |
  { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-16
