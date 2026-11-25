#!/usr/bin/env bash
# Judge a pull request into main. Run by .github/workflows/judge.yml from a copy
# of main's harness, in a checkout of main ($TWINX_REPO), in two phases:
#
#   judge.sh baseline   run nginx-tests against nginx (the reference) and
#                       against twinx built from main as it is
#   judge.sh pr         merge the pull request without committing, build and test
#                       it, run nginx-tests against it, measure coverage and
#                       write the verdict
#
# Everything that comes from the pull request (cargo build with its build
# scripts, cargo test, twinx) runs in a container that sees only a copy of the
# merged tree and a cargo directory, or, for twinx, its binary and the tests.
# The checkout with its .git, this harness and the results stay on the host,
# out of the containers' reach.
#
# Environment: TWINX_REPO, JUDGE_DIR (scratch space, outputs in $JUDGE_DIR/out),
# and for the pr phase BRANCH, PR_NUMBER, PR_HEAD and BASE (main's commit).
# PR_REF names a local ref to merge instead of fetching the pull request.
set -euo pipefail

HARNESS=$(cd "$(dirname "$0")" && pwd)
IMAGE=$(python3 -c "import sys; sys.path.insert(0, '$HARNESS'); import run_tests; print(run_tests.RUST_IMAGE)")
RUSTFLAGS_COVERAGE="-C instrument-coverage -C llvm-args=-runtime-counter-relocation"
OUT="$JUDGE_DIR/out"
mkdir -p "$OUT" "$JUDGE_DIR/cargo"
cd "$TWINX_REPO"

# Run a cargo command in the tree at $1, as this user, with the network only if $2 is "net".
cargo_in() {
  local tree=$1 network=$2 rustflags=$3
  shift 3
  local profiles=()
  # With UNIT_PROFILES set, the instrumented test binaries write their profiles there.
  if [ -n "${UNIT_PROFILES:-}" ]; then
    profiles=(-v "$UNIT_PROFILES:/unit-profiles" -e "LLVM_PROFILE_FILE=/unit-profiles/unit-%p-%m.profraw")
  fi
  docker run --rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    --network "$([ "$network" = net ] && echo bridge || echo none)" \
    -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTFLAGS="$rustflags" --tmpfs /tmp:rw,exec "${profiles[@]}" \
    -v "$JUDGE_DIR/cargo:/cargo" -v "$tree:$tree" -w "$tree" "$IMAGE" cargo "$@"
}

# Run cargo test in the tree at $1 with coverage; succeeds only when the tests do.
# Writes the share of src/ the unit tests run and their time to $2 (recorded, not judged).
unit_tests() {
  local tree=$1 out=$2 profiles="$JUDGE_DIR/unit-profiles" seconds=$SECONDS
  rm -rf "$profiles" && mkdir -p "$profiles" && chmod 0777 "$profiles"
  UNIT_PROFILES="$profiles" cargo_in "$tree" none "$RUSTFLAGS_COVERAGE" test --release --offline || return 1
  seconds=$((SECONDS - seconds))
  local objects=()
  mapfile -t objects < <(cargo_in "$tree" none "$RUSTFLAGS_COVERAGE" test --release --offline --no-run \
    --message-format=json 2>/dev/null | python3 -I -c '
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test"):
        print(m["executable"])')
  if ls "$profiles"/*.profraw >/dev/null 2>&1 && [ ${#objects[@]} -gt 0 ]; then
    docker run --rm --cap-drop ALL --security-opt no-new-privileges \
      -v "$tree:$tree:ro" -v "$profiles:/profiles:ro" "$IMAGE" sh -c '
        rustup component add llvm-tools-preview >/dev/null 2>&1
        bin=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n "s/^host: //p")/bin
        "$bin/llvm-profdata" merge -sparse /profiles/*.profraw -o /tmp/merged.profdata
        first=$1; shift
        "$bin/llvm-cov" export "$first" $(for o in "$@"; do printf -- "-object %s " "$o"; done) \
          -instr-profile=/tmp/merged.profdata -format=lcov --ignore-filename-regex="/registry/src/|/rustc/"' \
      sh "${objects[@]}" > "$out.lcov" \
      && python3 "$HARNESS/unit_coverage.py" --lcov "$out.lcov" --tree "$tree" \
        --seconds "$seconds" --out "$out" || true
  fi
}

# unit_tests beside nginx-tests: its output waits, so that the two do not mix.
start_unit_tests() {
  unit_tests "$@" > "$JUDGE_DIR/unit.log" 2>&1 &
  unit_tests_pid=$!
}

# The status of the unit tests started.
finish_unit_tests() {
  local status=0
  wait "$unit_tests_pid" || status=$?
  cat "$JUDGE_DIR/unit.log"
  return "$status"
}

# Build the tree at $1 and its unit tests, and copy twinx to $3, apart from the tests'
# container; succeeds only when cargo build does.
build() {
  local tree=$1 rustflags=$2 binary=$3
  rm -f "$binary"
  cargo_in "$tree" net "$rustflags" fetch || return 1
  # Only to build twinx and its tests at the same time: the next build decides, and
  # leaves out what only dev-dependencies turn on.
  cargo_in "$tree" none "$rustflags" build --release --offline --bins --tests || true
  cargo_in "$tree" none "$rustflags" build --release --offline || return 1
  [ ! -f "$tree/target/release/twinx" ] || cp "$tree/target/release/twinx" "$binary"
}

baseline() {
  local tree="$JUDGE_DIR/main" binary="$JUDGE_DIR/main-twinx"
  rm -rf "$tree" && mkdir -p "$tree"
  git archive HEAD | tar -x -C "$tree"
  if [ -f "$tree/Cargo.toml" ]; then
    build "$tree" "$RUSTFLAGS_COVERAGE" "$binary" || true
  fi
  python3 "$HARNESS/run_tests.py" --nginx --out "$OUT/reference.json"
  # Nothing reads these profiles: main is built and run as a pull request is.
  local profiles="$JUDGE_DIR/main-profiles" status=0
  rm -rf "$profiles" && mkdir -p "$profiles" && chmod 0777 "$profiles"
  start_unit_tests "$tree" "$OUT/unit-main.json"
  python3 "$HARNESS/run_tests.py" --profiles "$profiles" --twinx "$binary" --out "$OUT/baseline.json" \
    || status=$?
  finish_unit_tests || true
  return "$status"
}

fail_merge() {
  printf '## judge: fail\n\nThe pull request does not merge cleanly into main. Update the branch.\n' > "$OUT/comment.md"
  echo '{"passed": false, "problems": ["does not merge cleanly into main"]}' > "$OUT/verdict.json"
  exit 1
}

pr() {
  git config user.name "twinx-judge"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  if [ -n "${PR_REF:-}" ]; then
    git rev-parse -q --verify "$PR_REF" >/dev/null || fail_merge
    head=$(git rev-parse "$PR_REF")
  else
    git fetch -q origin "pull/$PR_NUMBER/head" || fail_merge
    head=$(git rev-parse FETCH_HEAD)
  fi
  [ "$head" = "$PR_HEAD" ] || fail_merge
  git merge -q --no-ff --no-commit "$head" || fail_merge

  # The containers get a copy of the merged tree, never the checkout and its .git.
  local tree="$JUDGE_DIR/pr" binary="$JUDGE_DIR/pr-twinx" build=skipped test=skipped
  rm -rf "$tree" && mkdir -p "$tree"
  tar -C "$TWINX_REPO" --exclude=./.git -cf - . | tar -C "$tree" -xf -
  if [ -f "$tree/Cargo.toml" ]; then
    if build "$tree" "$RUSTFLAGS_COVERAGE" "$binary"; then
      build=success
    else
      build=failure
    fi
  fi

  local profiles="$JUDGE_DIR/profiles"
  rm -rf "$profiles" && mkdir -p "$profiles" && chmod 0777 "$profiles"
  [ "$build" != success ] || start_unit_tests "$tree" "$OUT/unit.json"
  python3 "$HARNESS/run_tests.py" --profiles "$profiles" \
    --twinx "$binary" --out "$OUT/results.json" || true
  if [ "$build" = success ]; then
    finish_unit_tests && test=success || test=failure
  fi

  local lcov=()
  if ls "$profiles"/*.profraw >/dev/null 2>&1 && [ -x "$binary" ]; then
    docker run --rm --cap-drop ALL --security-opt no-new-privileges \
      -v "$binary:$binary:ro" -v "$profiles:/profiles:ro" "$IMAGE" sh -c '
        rustup component add llvm-tools-preview >/dev/null 2>&1
        bin=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n "s/^host: //p")/bin
        "$bin/llvm-profdata" merge -sparse /profiles/*.profraw -o /tmp/merged.profdata
        "$bin/llvm-cov" export "$0" -instr-profile=/tmp/merged.profdata -format=lcov \
          --ignore-filename-regex="/registry/src/|/rustc/"
        echo "=====REGIONS====="
        "$bin/llvm-cov" export "$0" -instr-profile=/tmp/merged.profdata -format=text -skip-functions \
          --ignore-filename-regex="/registry/src/|/rustc/"' "$binary" \
      > "$OUT/coverage.raw" \
      && sed '/^=====REGIONS=====$/,$d' "$OUT/coverage.raw" > "$OUT/tests.lcov" \
      && sed '1,/^=====REGIONS=====$/d' "$OUT/coverage.raw" > "$OUT/tests-regions.json" \
      && lcov=(--lcov "$OUT/tests.lcov" --regions "$OUT/tests-regions.json")
  fi
  python3 "$HARNESS/coverage.py" --base "$BASE" "${lcov[@]}" --out "$OUT/coverage.json" || true

  python3 "$HARNESS/judge.py" \
    --branch "$BRANCH" --base "$BASE" --head "$PR_HEAD" --build "$build" --test "$test" \
    --reference "$OUT/reference.json" --baseline "$OUT/baseline.json" \
    --results "$OUT/results.json" --coverage "$OUT/coverage.json" \
    --unit "$OUT/unit.json" --unit-main "$OUT/unit-main.json" \
    --verdict "$OUT/verdict.json" --comment "$OUT/comment.md"
}

"$1"
