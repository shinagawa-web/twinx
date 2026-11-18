# twinx

An experiment to find out how far an agent loop can take an HTTP server that behaves like nginx.

## Questions

| Question | Records that answer it |
|---|---|
| How much can be automated? | The number of issues closed automatically, and the number that stopped and waited for a human |
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

A shell script (the driver) runs the loop and calls Claude Code with `claude -p` once per iteration. Whether an issue is fixed is never decided from Claude Code's own report. The driver reruns the differential tests and decides.

```
driver
  ├─ take one issue from issues/open/
  ├─ create a fresh worktree
  ├─ the Fixer (claude -p) fixes that issue and exits
  ├─ the driver runs every differential test and cargo test
  │     ├─ the issue is fixed and nothing else broke → merge into main, move the issue to issues/fixed/
  │     └─ otherwise → discard the change, increment the failure count
  ├─ after 3 failures on the same issue, move it to issues/stuck/
  └─ next iteration
```

The Finder writes test cases (pairs of a configuration and a request), runs them against both nginx and twinx, and writes an issue file into `issues/open/` when the two differ. Only writing the test cases uses Claude Code. Running and comparing them is done by scripts.

## Where a human steps in

- Issues that land in `issues/stuck/`
- Whether to move on to the next stage
- Changes to the judging rules, such as adding a header that is excluded from comparison

Every intervention adds one row to `docs/interventions.md`. Decisions made before the experiment starts are recorded there too, as human decisions.

## Out of scope

- nginx's C modules and Lua (lua-nginx-module)
