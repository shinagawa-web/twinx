# One run of the loop

The schedule runs stage 4 since 2026-11-23 (#196). A human may also start a run by hand; a run that has started goes ahead.

A scheduled Claude Code session runs the loop as the Fixer, with model `claude-opus-5-5`, following `docs/fixer.md`.

| Role | Routine | Schedule |
|---|---|---|
| Fixer | `trig_01YX3pTLi2c3KYXT33CabyPp` | every hour at :30 (cron `30 * * * *`) |

Before twinx started over on nginx-tests (2026-11-20), a second session, the Finder (`trig_01GqFt2a2yGPCmAoq9UnXr3y`), wrote cases of its own; that role is gone. The very first run (`trig_012ER29uuypTqhUEnHtyZfrF`, 2026-11-18T23:30:00Z) was a single session that took both roles.

## Which files fail on main

The judge decides, not your own runs. The judge's comment on the most recently merged pull request lists them on its "Failing:" line and gives the passing counts. Your session's environment differs from the judge's (it has no IPv6, for one), so a file your own run skips or passes may still fail there; never take your own results as what passes on main.

Your own runs are for working on a file:

```
scripts/run.sh cargo build --release
scripts/run.sh python3 harness/run_tests.py --nginx --out results/nginx.json
scripts/run.sh python3 harness/run_tests.py --twinx target/release/twinx --reference results/nginx.json --out results/twinx.json
```

A file fails when a subtest that passes on nginx does not pass on twinx; the last command prints `FAIL` and those subtests. A file skipped here can only be checked by the judge.

An open failing file is one on the judge's "Failing:" line that has no open pull request from its branch (`claude/fix-<stage>-<file>`, without `.t`) and no open issue labelled `blocked` for it. The stage is done only when that line says `none`.

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

## Stalled

When a pull request still fails the judge at the end of the iteration you spent on it, and nothing outside your role is in the way (that would be blocked), leave it open, label it `stalled`, and comment what still fails and what you tried. Later runs leave it alone, and its file is not picked again while it is open. A human looks at stalled pull requests and removes the label to have it taken up again.

## A Fixer run

When a run starts, another may still be working. If a Fixer pull request (`claude/fix-*`) is open, is neither blocked nor labelled `stalled`, and had a commit, a comment or a judge run in the last 30 minutes, another run is on it: start nothing and end the run (below).

As many iterations as fit before the next run, which starts at minute 30 of the hour: start one only while the minute (`date +%M`) is 30 or more, or less than 15. Each one:

1. `git fetch --prune origin` and start from a fresh `origin/main`.
2. If one of your open pull requests says `Blocked by #<issue>` and that issue is closed, update its branch with main, remove the line, and wait for the judge as above. Otherwise:
3. If one of your open pull requests failed the judge and is not labelled `stalled`, fix it as the judge's comment says. If you cannot make it pass in this run, it is stalled (below). Otherwise:
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

The tokens come from `python3 harness/usage.py`, which reads this session's own transcript. The passing counts are always those of the judge's comment on the most recently merged pull request, never your own results.

## What you never do

- Push to main. The ruleset refuses it anyway; every change goes through a pull request.
- Merge a pull request whose `judge` check has not passed, or one that is not yours.
- Change `harness/`, `.github/`, `scripts/`, `status/` or the documents. If one of them is in your way, you are blocked.

## Running commands

Run every build and test through `scripts/run.sh`: in place on Linux, inside the Lima VM on macOS. `results/*.json` holds, for each nginx-tests file, every subtest's result (`ok`, `not ok` or `skip`), the plan, and the end of its error output.
