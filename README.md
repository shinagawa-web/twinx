# twinx

An experiment to find out how far an agent loop can take an HTTP server that behaves like nginx.

## Questions

| Question | Records that answer it |
|---|---|
| How much can be automated? | The number of cases made to pass automatically, and the number that got stuck and waited for a human |
| Where does a human have to step in? | The intervention log (`docs/interventions.md`) |
| What quality do we get, in how much time and at what cost? | The differential test pass rate over elapsed time, the number of nginx-tests passed, and the time and tokens spent per iteration |

## Approach

Real nginx is the reference. nginx runs in Docker and reads the same configuration file as twinx, and both receive the same requests. A case passes when the status, headers and body match.

One nginx version is pinned when the comparison harness is built, and it does not change during the experiment.

If the official nginx test suite (nginx-tests) can be pointed at the twinx binary, it is also used to judge pass or fail. Whether it can is checked when the comparison harness is built.

## Stages

Time spent, pass rate and the number of interventions are recorded separately for each stage. Every differential test from earlier stages keeps running in later stages.

| Stage | Scope |
|---|---|
| 1 | Static file serving and reverse proxying over HTTP/1.1: server and location selection, root, index, try_files, return, add_header, proxy_pass, upstream |
| 2 | gzip |
| 3 | TLS |
| 4 | HTTP/2 |
| 5 | Caching (proxy_cache) |

## The automated loop

The work queue is the set of cases that fail on main: each failing case holds the configuration, the requests and what nginx answered. There are no separate issue files.

Claude Code works in two roles and only ever pushes a branch. It never decides whether its own change is good:

- The Fixer picks one failing case, changes the Rust code until that case passes, and pushes `claude/fix-<stage>-<case>`.
- The Finder writes new cases for the current stage and pushes `claude/find-<name>`.

The judge is a GitHub Actions workflow (`.github/workflows/judge.yml`, `harness/judge.py`). For every push to a `claude/` branch it merges the branch into main without committing, then builds, runs `cargo test` and runs every case against nginx and twinx.

```
push to claude/...
  ├─ the branch touched only what its role may touch?
  │     Fixer: src/, tests/, benches/, Cargo.toml, Cargo.lock
  │     Finder: new files under cases/
  ├─ build and cargo test pass?
  ├─ every case that passed on main still passes?
  ├─ (Fixer) the case it names now passes?
  │
  ├─ yes → merge into main, update status/passing.txt, delete the branch
  └─ no  → append the reason to status/attempts.tsv on main
```

A case with three failed attempts in `status/attempts.tsv` is stuck and waits for a human.

`scripts/run.sh` is the one way to run a command: in place on Linux, inside the Lima VM on macOS.

## Where a human steps in

- Stuck cases
- Whether to move on to the next stage
- Changes to the judging rules, such as adding a header that is excluded from comparison

Every intervention adds one row to `docs/interventions.md`. Decisions made before the experiment starts are recorded there too, as human decisions.

## Out of scope

- nginx's C modules and Lua (lua-nginx-module)
