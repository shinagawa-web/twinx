# Fixer

Make one failing nginx-tests file pass by changing twinx, without breaking any subtest that passes on main.

## Pick the file

Among the open failing files (see `docs/loop.md`), take the one in the lowest stage (`harness/stages.toml`), and within a stage the first by name.

## What twinx is

- A Rust binary built by `cargo build --release` at `target/release/twinx`.
- nginx-tests runs it the way it runs nginx (`lib/Test/Nginx.pm` in nginx-tests): `twinx -p <test dir>/ -c nginx.conf -e error.log -g "pid <test dir>/nginx.pid; error_log <test dir>/error.log debug;"`, waits for the pid file, sends requests, and stops it with SIGQUIT. It reads `twinx -V` to tell which modules are available.
- It reads nginx's configuration language and behaves as nginx 1.30.6 does with that configuration. When nginx refuses a configuration, twinx refuses it too.
- In the pages it generates, twinx names itself `twinx/<version in Cargo.toml>`, never nginx.
- The judge runs it inside the nginx-tests container, as an unprivileged user, with no network but loopback, a read-only filesystem except `/tmp`, and no nginx in it. `harness/run_tests.py` runs it the same way.
- The judge builds it with Rust 1.100.0 (`rust-toolchain.toml`).

## How to fix

1. Run the file (`scripts/run.sh python3 harness/run_tests.py --twinx target/release/twinx --reference results/nginx.json <file>.t`) and read the file itself in nginx-tests: its configuration, its requests and what it expects. The nginx-tests image holds it under `/nginx-tests`.
2. Implement the nginx behavior the file tests, as nginx documents and does it, for any configuration and any request, not only the ones in the file. Never recognize the tests: no special handling of their file names, ports, paths or backends.
3. Crates from crates.io may be used. Prefer ones whose behavior you can make match nginx byte for byte.
4. Implement only what nginx-tests needs. The judge builds twinx with coverage instrumentation, runs the stage's files, and rejects the pull request when nginx-tests run less than 99% of the executable lines it adds. Rust unit tests do not count toward this.
5. Add Rust unit tests in `src/` or `tests/` for the parts you write.
6. Before pushing, build, run `cargo test` and run every file of the current stages against nginx's results. No subtest that passes on main may fail. A file your environment skips is checked only by the judge.

## What to open

- One pull request per file, from the branch `claude/fix-<stage>-<file without .t>`, for example `claude/fix-stage1-index`.
- Only `src/`, `tests/`, `benches/`, `Cargo.toml` and `Cargo.lock` may change. The judge rejects anything else.
- The title and the commit message say which nginx behavior was implemented. Pull requests are squash-merged, so the title becomes the commit on main.
