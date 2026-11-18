#!/usr/bin/env bash
# Run a command from the repository root on a Linux machine with Docker.
#
# On Linux (a cloud session, a CI runner) the command runs in place.
# On macOS the repository is copied into the Lima VM named by $VM (default
# twinx), the command runs there, and results/ is copied back. The VM keeps
# target/ between runs so builds stay incremental.
#
#   scripts/run.sh python3 harness/compare.py --out results/latest.json
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: scripts/run.sh <command> [args ...]" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)

if [ "$(uname -s)" = Linux ]; then
  cd "$root"
  mkdir -p results
  exec "$@"
fi

vm=${VM:-twinx}
set +e
(cd "$root" && git ls-files -z -co --exclude-standard | COPYFILE_DISABLE=1 tar --no-xattrs --null -T - -cf -) |
  limactl shell "$vm" -- bash -lc '
    mkdir -p ~/twinx
    find ~/twinx -mindepth 1 -maxdepth 1 ! -name target -exec rm -rf {} +
    tar -C ~/twinx -xf - && cd ~/twinx && mkdir -p results && "$@"' bash "$@"
rc=${PIPESTATUS[1]}
set -e
mkdir -p "$root/results"
limactl shell "$vm" -- sh -c 'tar -C ~/twinx/results -cf - .' | tar -C "$root/results" -xf -
exit "$rc"
