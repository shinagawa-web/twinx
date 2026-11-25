# twinx

An experiment to find out how far an agent loop can take an HTTP server that behaves like nginx.

## Questions

| Question | Records that answer it |
|---|---|
| How much can be automated? | The number of nginx-tests files made to pass automatically, and the number of blocked issues the loop opened for a human |
| Where does a human have to step in? | The intervention log (`docs/interventions.md`) |
| What quality do we get, in how much time and at what cost? | The nginx-tests pass rate over elapsed time, and the time and tokens spent per iteration ("Fixer runs", #44) |

## Approach

twinx is judged by nginx's own test suite, nginx-tests (https://github.com/nginx/nginx-tests), pinned to one commit. nginx-tests starts the server under test from the binary it is given, writes each test's configuration, sends requests and checks the answers.

nginx 1.30.6, pinned by its Docker image digest, is the reference: it passes every nginx-tests file at that commit. A subtest is expected of twinx only when it passes on nginx in the same environment, and a file passes when twinx passes every subtest of it that nginx passes.

## Stages

Each stage is a list of nginx-tests files (`harness/stages.toml`). A stage is done when every file in it passes on main, or when the human cuts it; either way main is tagged and released, and the files that do not pass yet move to the next stage. Time spent, pass rate and the number of interventions are recorded separately for each stage, and the files of earlier stages keep running in later stages.

| Stage | Scope | Files |
|---|---|---|
| 1 | Static file serving and reverse proxying over HTTP/1.1 | cut at v0.1.0 (2026-11-20): the 12 files that passed then |
| 2 | What stage 1 left, and gzip | done at v0.2.0 (2026-11-22): the stage 1 files that did not pass at v0.1.0, those that also need the gzip, gunzip or gzip_static modules, and twinx's own tests |
| 3 | TLS | done at v0.3.0 (2026-11-23): those that also need only http_ssl and the test client's TLS features (40; HTTP/2, HTTP/3, stream and mail wait) |
| 4 | HTTP/2 | done at v0.4.0 (2026-11-24): those that also need only http_v2 (33; grpc, HTTP/3, caching and other modules wait) |
| 5 | Caching (proxy_cache), and kept connections to servers | done at v0.5.0 (2026-11-25): those that also need only cache and upstream_keepalive (30; fastcgi, grpc, HTTP/3 and other modules wait), and twinx's own tests of behaviour nginx-tests does not check (29) |
| 6 | What the files of stage 5 leave unchecked | twinx's own tests of behaviour nginx-tests does not check |

## The automated loop

The work queue is the set of nginx-tests files in the current stages that fail on main.

The Fixer, a scheduled Claude Code session, picks one failing file, changes the Rust code until it passes, and opens a pull request from `claude/fix-<stage>-<file>` with auto-merge on. It does not decide whether its change is good; the judge does. main's ruleset (`main requires judge`) accepts a merge only through a pull request whose `judge` check passed on a branch that is up to date with main, with no exceptions, the owner included.

The judge is a GitHub Actions workflow (`.github/workflows/judge.yml`, `harness/judge.sh`, `harness/judge.py`). It runs on `pull_request_target`, so the workflow and the harness always come from main, never from the pull request. The job that runs the pull request's code can only read the repository, and it runs that code (cargo build with its build scripts, cargo test, twinx) only in containers: the build sees a copy of the merged tree, and twinx runs inside the nginx-tests container, from which the reference nginx is removed, with no network but loopback. For every pull request it takes the results of nginx-tests against nginx and against main as it is (`.github/workflows/baseline.yml` measures them when main changes; where they are missing, the judge does), merges the pull request into main without committing, builds twinx with coverage instrumentation, runs `cargo test`, runs nginx-tests again, and comments the verdict on the pull request.

```
pull request into main
  ├─ it touched only what its role may touch?
  │     Fixer: src/, tests/, benches/, Cargo.toml, Cargo.lock
  │     anything not under claude/: a human, no limit
  ├─ build and cargo test pass?
  ├─ every subtest that passes on main still passes?
  ├─ (Fixer) the file it names now passes?
  ├─ (Fixer) nginx-tests run at least 99% of the lines it adds?
  │
  ├─ yes → judge passes, auto-merge merges it
  └─ no  → judge fails with the reasons in a comment; the pull request stays open
```

Files that fail on main are allowed: they are the Fixer's work queue. A green `judge` on main means main did not get worse, not that every file passes.

A pull request the judge fails stays open, and the Fixer pushes fixes to it.

When the Fixer judges that it cannot fix something within its role, it is blocked. It opens an issue labelled `blocked` saying what it was working on, why it cannot go on and what a human has to decide, links the issue from its pull request, leaves the pull request open and sends a push notification. A file with an open `blocked` issue is not picked again. A human decides how to fix it, fixes it and closes the issue. The next Fixer run first takes up the pull requests whose `blocked` issue was closed, updating them with main so the judge runs again.

`scripts/run.sh` is the one way to run a command: in place on Linux, inside the Lima VM on macOS.

## Where a human steps in

Only through what the judge enforces: the harness, the judging rules, the stage lists and these documents, changed by pull requests that pass the same `judge` check.

- Blocked issues: deciding how to fix what the loop could not, and fixing it
- Stalled pull requests: files the Fixer could not make pass within a run (label `stalled`)
- Whether to move on to the next stage (`status/stage.txt`)
- Changes to the judging rules, such as adding a header that is excluded from comparison

## Issues

| Kind | Opened by | Closed by |
|---|---|---|
| Plan (label `plan`): what the human follows, such as finishing a stage | the human | the human |
| Harness work: a change to the harness, the judging rules, the stage lists or the documents | the human | the pull request that makes the change, when it merges |
| Blocked (label `blocked`): something the loop cannot fix within its role | the Fixer | the human, after fixing it |
| Record (label `record`): "Fixer runs" (#44), one comment per run with its time, tokens and results | the human, once | never |

The human includes the Claude Code session the human instructs; the loop is the scheduled Fixer.

Every intervention adds one row to `docs/interventions.md`. Decisions made before the experiment starts are recorded there too, as human decisions.

## Out of scope

- nginx's C modules and Lua (lua-nginx-module)
