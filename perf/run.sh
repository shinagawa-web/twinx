#!/usr/bin/env bash
# Measures twinx against nginx: a tag,  perf/run.sh v0.4.0 [--quick]
# a twinx pull request,                perf/run.sh --pr 123 [--quick]
# or a twinx commit or branch          perf/run.sh --ref main [--quick]
#
# With --group tls, only the scenarios of that group (perf/lib/scenarios.py) are measured;
# with --scenario <name>, given once for each, only the scenarios of those exact names.
#
# A tag: fetches its binary for this architecture from its release or, when the
# release has none, builds it from the tag's source in twinx's pinned Rust image.
# A pull request: builds its head the same way; a ref, its commit.
# Then runs nginx, twinx and perf/lib/bench.py in one container with no network.
# On macOS everything runs in the Lima VM named by $VM (default twinx), in the directory
# $VM_DIR of its home (default perf-run).
# Writes perf/results/<arch>/<tag>.json, and nginx's of it to perf/results/<arch>/nginx.json.
# With --pr, --ref, --group or --scenario, only perf/work/<what>/<arch>/<group, or scenarios,
# or what>.json, which is not committed, and nginx is measured only in the scenarios that
# perf/results/<arch>/nginx.json does not have, unless --measure-nginx is given (a group of
# a tag's run of all the scenarios in CI).
set -euo pipefail
pr= ref=
if [ "${1:-}" = --pr ]; then
  pr=${2:?usage: perf/run.sh --pr <number> [bench arguments]}
  [[ "$pr" =~ ^[0-9]+$ ]] || { echo "not a pull request number: $pr" >&2; exit 2; }
  name=pr-$pr
  shift 2
elif [ "${1:-}" = --ref ]; then
  ref=${2:?usage: perf/run.sh --ref <commit or branch> [bench arguments]}
  [[ "$ref" =~ ^[A-Za-z0-9._/-]+$ && "$ref" != *..* ]] || { echo "not a commit or branch: $ref" >&2; exit 2; }
  name=ref-${ref//\//-}
  shift 2
else
  name=${1:?usage: perf/run.sh <tag> [--group <group>] [bench arguments], or perf/run.sh --pr <number>, or perf/run.sh --ref <commit or branch>}
  shift
fi
tag=$name group= named= measure_nginx= rest=()
while [ $# -gt 0 ]; do
  case "$1" in
    --measure-nginx) measure_nginx=1; shift ;;
    --group) group=${2:?--group takes a group}; rest+=(--group "$group"); shift 2 ;;
    --scenario) named=scenarios; rest+=(--scenario "${2:?--scenario takes the name of a scenario}"); shift 2 ;;
    *) rest+=("$1"); shift ;;
  esac
done
set -- ${rest[@]+"${rest[@]}"}
root=$(cd "$(dirname "$0")" && pwd)
repo=shinagawa-web/twinx
rust_image=rust@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37

if [ "$(uname -s)" = Darwin ]; then
  vm=${VM:-twinx} vm_dir=${VM_DIR:-perf-run}
  [[ "$vm_dir" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "not a directory name: $vm_dir" >&2; exit 2; }
  arch=$(limactl shell "$vm" uname -m)
else
  arch=$(uname -m)
fi
work=$root/work/$name/$arch
if [ -n "$pr$ref$group$named" ]; then
  results=$work
else
  results=$root/results/$arch
fi
mkdir -p "$work" "$results"
out=${group:-${named:-$name}}.json
rm -f "$work/kept/nginx.json"
if [ "$results" = "$work" ] && [ -z "$measure_nginx" ]; then
  if [ -f "$root/results/$arch/nginx.json" ]; then
    mkdir -p "$work/kept"
    cp "$root/results/$arch/nginx.json" "$work/kept/nginx.json"
    set -- "$@" --kept-nginx /kept/nginx.json
  else
    echo "no perf/results/$arch/nginx.json: nginx is measured too" >&2
  fi
fi

# Fetched with the local gh login; nothing inside the container reaches the network.
# Puts twinx at $1 (a tag or a commit): its release's binary in $work/twinx, or its
# source in $work/twinx.tar.gz. kind and at say which.
kind= at=
fetch() {
  local ref=$1 file=$work/twinx
  kind=source at=$ref
  if [[ "$ref" == v* ]] && grep -qx "twinx-$ref-$arch-linux-gnu" <<<"$(gh release view "$ref" -R "$repo" --json assets -q '.assets[].name' 2>/dev/null)"; then
    kind=binary
  fi
  if [ "$(cat "$file.ref" 2>/dev/null)" != "$kind:$ref" ]; then
    rm -f "$file" "$file.ref"
    if [ "$kind" = binary ]; then
      gh release download "$ref" -R "$repo" -p "twinx-$ref-$arch-linux-gnu" -O "$file"
      chmod +x "$file"
    else
      gh api "repos/$repo/tarball/$ref" > "$file.tar.gz"
    fi
    echo "$kind:$ref" > "$file.ref"
  fi
}

if [ -n "$pr" ]; then
  head=$(gh pr view "$pr" -R "$repo" --json headRefOid -q .headRefOid)
  fetch "$head"
  labels=(--twinx-label "#$pr ${head:0:7}")
elif [ -n "$ref" ]; then
  head=$(gh api "repos/$repo/commits/$ref" -q .sha)
  fetch "$head"
  labels=(--twinx-label "$ref ${head:0:7}")
else
  fetch "$tag"
  labels=()
fi

inside='
set -euo pipefail
cd "$1"; name=$2; kind=$3; at=$4; rust_image=$5; shift 5
work=work/$name/$(uname -m)
# Builds the source in tarball $1 into binary $2, unless $2 was already built from it ($3, a commit).
# The registry and target/ are kept in perf/work/build, between runs and, by perf.yml, between
# jobs: only twinx itself is compiled again.
build() {
  [ -f "$2" ] && [ "$(cat "$2.built" 2>/dev/null)" = "$3" ] && return
  local src=$work/src-$(basename "$2") cache=work/build/$(uname -m) lto=()
  rm -rf "$src" && mkdir -p "$src" "$cache/cargo" "$cache/target"
  # Dated now (-m): cargo takes a source older than the last build in target/ as built.
  tar -xzmf "$1" -C "$src" --strip-components 1
  # Without fat LTO, twinx compiles in two thirds of the time, and its CPU per request is a
  # few percent above that of a release build, which does not hide a scenario far above nginx.
  # A tag is recorded, so it is built as it is released.
  case $name in pr-*|ref-*) lto=(-e CARGO_PROFILE_RELEASE_LTO=false -e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16) ;; esac
  docker run --rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -e HOME=/tmp -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target "${lto[@]}" --tmpfs /tmp:rw,exec \
    -v "$PWD/$cache/cargo:/cargo" -v "$PWD/$cache/target:/target" -v "$PWD/$src:/src" -w /src \
    "$rust_image" cargo build --release --locked -q
  cp "$cache/target/release/twinx" "$2"
  echo "$3" > "$2.built"
}
binary=$work/twinx
[ "$kind" = binary ] || { build "$work/twinx.tar.gz" "$work/twinx-built" "$at"; binary=$work/twinx-built; }
rm -rf "$work/out" && mkdir -p "$work/out" "$work/kept"
# Pushed by .github/workflows/perf-image.yml from main. Built here when it cannot be pulled:
# with no way to ghcr.io, or when perf/lib/Dockerfile or what it copies is not on main yet.
image=ghcr.io/shinagawa-web/twinx/perf:$(bash lib/image-tag.sh)
docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null 2>&1 ||
  docker build -q -t "$image" lib >/dev/null
# Loopback only. 1000 clients and their proxied connections need file
# descriptors, local ports and, up to v0.3.0, a thread per connection.
exec docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  --memory 4g --pids-limit 32768 --ulimit nofile=65536:65536 \
  --sysctl net.ipv4.ip_local_port_range="1024 65535" --sysctl net.ipv4.tcp_tw_reuse=1 \
  --tmpfs /work:rw,exec,size=2g \
  -v "$PWD/$binary:/twinx/twinx:ro" -v "$PWD/$work/out:/results" -v "$PWD/$work/kept:/kept:ro" \
  "$image" python3 /perf/bench.py --twinx /twinx/twinx \
  --tag "$name" --out "/results/$name.json" "$@"
'

if [ "$(uname -s)" = Darwin ]; then
  limactl shell "$vm" -- bash -c 'rm -rf ~/"$0"/lib && mkdir -p ~/"$0"' "$vm_dir"
  (cd "$root" && { git ls-files -z -co --exclude-standard -- . ':!results' | while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done
                   for f in "work/$name/$arch/"{twinx,twinx.tar.gz,kept/nginx.json}; do
                     [ -f "$f" ] && printf '%s\0' "$f"; done; true; } |
     COPYFILE_DISABLE=1 tar --no-xattrs --null -T - -cf - 2>/dev/null) |
    limactl shell "$vm" -- bash -c 'tar -C ~/"$0" -xf -' "$vm_dir"
  set +e
  limactl shell "$vm" -- bash -c 'cd ~/"$1" && s=$0 && shift && bash -c "$s" bash "$PWD" "$@"' "$inside" "$vm_dir" "$name" "$kind" "$at" "$rust_image" ${labels[@]+"${labels[@]}"} "$@"
  rc=$?
  set -e
  limactl shell "$vm" -- bash -c 'cat ~/"$2"/work/"$0"/"$1"/out/"$0".json' "$name" "$arch" "$vm_dir" > "$results/$out"
else
  set +e
  bash -c "$inside" bash "$root" "$name" "$kind" "$at" "$rust_image" ${labels[@]+"${labels[@]}"} "$@"
  rc=$?
  set -e
  cp "$work/out/$name.json" "$results/$out"
fi
if [ "$results" = "$work" ]; then
  echo "wrote $results/$out"
elif [ "$rc" = 0 ]; then
  python3 "$root/lib/keep.py" "$results/$out" "$results/nginx.json"
fi
exit "$rc"
