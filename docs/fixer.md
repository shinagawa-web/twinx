# Fixer

Make one failing case pass by changing twinx, without breaking any case that passes.

## Pick the case

Among the open failing cases (see `docs/loop.md`), take the one in the lowest stage; within a stage, the one with the fewest closed pull requests from its branch, and among those the first by directory name.

## What twinx is

- A Rust binary built by `cargo build --release` at `target/release/twinx`, started as `twinx -c <path to nginx.conf>` and staying in the foreground.
- It reads nginx's configuration language and behaves as nginx 1.30.6 does with that configuration. The harness wraps every case in the same top-level configuration (`harness/compare.py`, `WRAPPER`), so the directives there must be accepted.
- When nginx refuses a configuration, twinx refuses it too and exits without listening. A directive twinx does not implement yet is refused the same way, naming the directive.
- In the pages it generates, twinx names itself `twinx/<version in Cargo.toml>`, never nginx.
- The judge runs twinx in a container as an unprivileged user, with the case directory read-only and only `/tmp` writable. `harness/compare.py --sandbox` runs it the same way.

## How to fix

1. Read the case (`case.toml`, `files/`) and run it to see what nginx answers and what twinx answers.
2. Implement the nginx behavior behind the difference, as nginx documents and does it, for any configuration and any request, not only the ones in the case. Never recognize the harness: no special handling of case names, paths under /tmp/twinx-cases, port 18080 or the echo backend.
3. Crates from crates.io may be used. Prefer ones whose behavior you can make match nginx byte for byte.
4. Implement only what the cases need. The judge builds twinx with coverage instrumentation, runs every case, and rejects the pull request when the cases run less than 99% of the executable lines it adds. Rust unit tests do not count toward this. A feature no case exercises waits until the Finder writes a case for it.
5. Add Rust unit tests in `src/` or `tests/` for the parts you write.
6. Before pushing, build, run `cargo test` and run every case (`scripts/run.sh python3 harness/compare.py --out results/all.json`). No case that passes on main may fail.

## What to open

- One pull request per case, from the branch `claude/fix-<stage>-<case>`, for example `claude/fix-stage1-static-file`.
- Only `src/`, `tests/`, `benches/`, `Cargo.toml` and `Cargo.lock` may change. The judge rejects anything else.
- The title and the commit message say which nginx behavior was implemented. Pull requests are squash-merged, so the title becomes the commit on main.

If pull requests for the same case were closed before, read the judge's comments on them before trying again.
