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
  docker run --rm --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    --network "$([ "$network" = net ] && echo bridge || echo none)" \
    -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTFLAGS="$rustflags" --tmpfs /tmp:rw,exec \
    -v "$JUDGE_DIR/cargo:/cargo" -v "$tree:$tree" -w "$tree" "$IMAGE" cargo "$@"
}

# Build the tree at $1; succeeds only when the build does.
build() {
  local tree=$1 rustflags=$2
  cargo_in "$tree" net "$rustflags" fetch && cargo_in "$tree" none "$rustflags" build --release --offline
}

baseline() {
  local tree="$JUDGE_DIR/main"
  rm -rf "$tree" && mkdir -p "$tree"
  git archive HEAD | tar -x -C "$tree"
  if [ -f "$tree/Cargo.toml" ]; then build "$tree" "" || true; fi
  python3 "$HARNESS/run_tests.py" --nginx --out "$OUT/reference.json"
  python3 "$HARNESS/run_tests.py" --twinx "$tree/target/release/twinx" --out "$OUT/baseline.json"
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
  local tree="$JUDGE_DIR/pr" build=skipped test=skipped
  rm -rf "$tree" && mkdir -p "$tree"
  tar -C "$TWINX_REPO" --exclude=./.git -cf - . | tar -C "$tree" -xf -
  if [ -f "$tree/Cargo.toml" ]; then
    if build "$tree" "$RUSTFLAGS_COVERAGE"; then
      build=success
      cargo_in "$tree" none "$RUSTFLAGS_COVERAGE" test --release --offline && test=success || test=failure
    else
      build=failure
    fi
  fi

  local profiles="$JUDGE_DIR/profiles"
  rm -rf "$profiles" && mkdir -p "$profiles" && chmod 0777 "$profiles"
  python3 "$HARNESS/run_tests.py" --profiles "$profiles" \
    --twinx "$tree/target/release/twinx" --out "$OUT/results.json" || true

  local lcov=()
  if ls "$profiles"/*.profraw >/dev/null 2>&1 && [ -x "$tree/target/release/twinx" ]; then
    docker run --rm --cap-drop ALL --security-opt no-new-privileges \
      -v "$tree:$tree:ro" -v "$profiles:/profiles:ro" "$IMAGE" sh -c '
        rustup component add llvm-tools-preview >/dev/null 2>&1
        bin=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n "s/^host: //p")/bin
        "$bin/llvm-profdata" merge -sparse /profiles/*.profraw -o /tmp/merged.profdata
        "$bin/llvm-cov" export "$0" -instr-profile=/tmp/merged.profdata -format=lcov \
          --ignore-filename-regex="/registry/src/|/rustc/"' "$tree/target/release/twinx" \
      > "$OUT/tests.lcov" && lcov=(--lcov "$OUT/tests.lcov")
  fi
  python3 "$HARNESS/coverage.py" --base "$BASE" "${lcov[@]}" --out "$OUT/coverage.json" || true

  python3 "$HARNESS/judge.py" \
    --branch "$BRANCH" --base "$BASE" --head "$PR_HEAD" --build "$build" --test "$test" \
    --reference "$OUT/reference.json" --baseline "$OUT/baseline.json" \
    --results "$OUT/results.json" --coverage "$OUT/coverage.json" \
    --verdict "$OUT/verdict.json" --comment "$OUT/comment.md"
}

"$1"
