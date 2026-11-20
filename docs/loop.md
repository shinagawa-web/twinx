# One run of the loop

The schedule is paused since 2026-11-20T02:25Z, while twinx starts over on nginx-tests. A human may start a run by hand; a run that has started goes ahead.

A scheduled Claude Code session runs the loop as the Fixer, with model `claude-opus-5-5`, following `docs/fixer.md`.

| Role | Routine | Schedule |
|---|---|---|
| Fixer | `trig_01YX3pTLi2c3KYXT33CabyPp` | every hour at :30 (cron `30 * * * *`) |

Before twinx started over on nginx-tests (2026-11-20), a second session, the Finder (`trig_01GqFt2a2yGPCmAoq9UnXr3y`), wrote cases of its own; that role is gone. The very first run (`trig_012ER29uuypTqhUEnHtyZfrF`, 2026-11-18T23:30:00Z) was a single session that took both roles.

## Which files fail on main

Find them yourself on a fresh `origin/main`; nothing else records them:

```
scripts/run.sh cargo build --release
scripts/run.sh python3 harness/run_tests.py --nginx --out results/nginx.json
scripts/run.sh python3 harness/run_tests.py --twinx target/release/twinx --reference results/nginx.json --out results/twinx.json
```

A file fails when a subtest that passes on nginx does not pass on twinx; the last command prints `FAIL` and those subtests. With no `Cargo.toml` on main there is no twinx yet, and every file fails.

An open failing file is one that fails on main, has no open pull request from its branch (`claude/fix-<stage>-<file>`, without `.t`) and no open issue labelled `blocked` for it.

## Pull requests

Every change reaches main through a pull request that the `judge` check passes. Use whichever GitHub tools the session has; which ones work has changed from one run to the next.

- Open the pull request against main with squash auto-merge turned on, so it merges as soon as the judge passes. If auto-merge cannot be turned on, merge it with squash yourself once the check passes.
- Wait, for up to 20 minutes, until it is merged.
- When the judge fails, it comments the reasons on the pull request. Fix them and push to the same branch; the judge runs again. Never close the pull request.
- When main moved and the branch is behind, update the branch and keep waiting.

## Blocked

When something outside your role keeps a file from passing (the harness, nginx-tests, the judging rules, a decision only a human can make), stop working on it:

1. Open an issue labelled `blocked`: the file, what fails, why you cannot fix it within your role, and what a human has to decide.
2. Write `Blocked by #<issue>` in the pull request's description and leave the pull request open.
3. Send a push notification with the issue's link.
4. Go on with the next open failing file.

A human fixes it and closes the issue.

## A Fixer run

Up to three iterations. Each one:

1. `git fetch --prune origin` and start from a fresh `origin/main`.
2. If one of your open pull requests says `Blocked by #<issue>` and that issue is closed, update its branch with main, remove the line, and wait for the judge as above. Otherwise:
3. If one of your open pull requests failed the judge, fix it as the judge's comment says. Otherwise:
4. If there is no open failing file, stop. Otherwise fix one as `docs/fixer.md` says, open the pull request and wait for it as above.

## At the end of a run

Before you end, however the run ends (merged, blocked, nothing to do), add one comment to the issue "Fixer runs" (#44):

```
started: <when the run fired>
ended: <now>
tokens: input <n>, output <n>, cache written <n>, cache read <n>, model calls <n>
pull requests: opened <#…>, merged <#…>
passing on main: <files> of <files> files, <subtests> of <subtests> subtests
```

The tokens come from `python3 harness/usage.py`, which reads this session's own transcript. The passing counts are those of the judge's comment on the most recently merged pull request, or the run's own results when nothing merged.

## What you never do

- Push to main. The ruleset refuses it anyway; every change goes through a pull request.
- Merge a pull request whose `judge` check has not passed, or one that is not yours.
- Change `harness/`, `.github/`, `scripts/`, `status/` or the documents. If one of them is in your way, you are blocked.

## Running commands

Run every build and test through `scripts/run.sh`: in place on Linux, inside the Lima VM on macOS. `results/*.json` holds, for each nginx-tests file, every subtest's result (`ok`, `not ok` or `skip`), the plan, and the end of its error output.
