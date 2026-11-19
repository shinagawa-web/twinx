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

Claude Code works in two roles. Neither decides whether its own change is good; the judge does:

- The Fixer picks one failing case, changes the Rust code until that case passes, and opens a pull request from `claude/fix-<stage>-<case>`.
- The Finder writes new cases for the current stage and opens a pull request from `claude/find-<name>`.

Both turn on auto-merge when they open the pull request. main's ruleset (`main requires judge`) accepts a merge only through a pull request whose `judge` check passed on a branch that is up to date with main, with no exceptions, the owner included. Whoever presses merge, the judge decides.

The judge is a GitHub Actions workflow (`.github/workflows/judge.yml`, `harness/judge.py`). It runs on `pull_request_target`, so the workflow and the harness always come from main, never from the pull request. The job that runs the pull request's code can only read the repository, and it runs that code (cargo build with its build scripts, cargo test, twinx) only in containers that see a copy of the merged tree, never the harness or the results (`harness/judge.sh`). For every pull request it runs every case against main as it is, merges the pull request into main without committing, builds twinx with coverage instrumentation, runs `cargo test`, runs every case again, and comments the verdict on the pull request.

```
pull request into main
  ├─ it touched only what its role may touch?
  │     Fixer: src/, tests/, benches/, Cargo.toml, Cargo.lock
  │     Finder: new files under cases/
  │     anything else: a human, no limit
  ├─ build and cargo test pass?
  ├─ every case that passes on main still passes?
  ├─ (Fixer) the case it names now passes?
  ├─ (Fixer) the cases run at least 99% of the lines it adds?
  │
  ├─ yes → judge passes, auto-merge merges it
  └─ no  → judge fails with the reasons in a comment; the pull request stays open
```

Cases that fail on main are allowed: they are the Fixer's work queue. A green `judge` on main means main did not get worse, not that every case passes.

A case is stuck after three pull requests for it were closed without being merged, and waits for a human.

`scripts/run.sh` is the one way to run a command: in place on Linux, inside the Lima VM on macOS.

## Where a human steps in

Only through what the judge enforces: the harness, the judging rules, the cases and these documents, changed by pull requests that pass the same `judge` check.

- Stuck cases
- Whether to move on to the next stage (`status/stage.txt`)
- Changes to the judging rules, such as adding a header that is excluded from comparison

Every intervention adds one row to `docs/interventions.md`. Decisions made before the experiment starts are recorded there too, as human decisions.

## Out of scope

- nginx's C modules and Lua (lua-nginx-module)
