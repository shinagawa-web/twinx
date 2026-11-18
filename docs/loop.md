# One run of the loop

Two scheduled Claude Code sessions run the loop, both with model `claude-opus-5-5`. Each session has one role and never takes the other, so the Finder writes cases without knowing how twinx is written.

| Role | Routine | Schedule | Rules |
|---|---|---|---|
| Fixer | `trig_01YX3pTLi2c3KYXT33CabyPp` | every hour at :30 (cron `30 * * * *`) | `docs/fixer.md` |
| Finder | `trig_01GqFt2a2yGPCmAoq9UnXr3y` | every hour at :49 (cron `49 * * * *`); its checkout leaves out `src/`, `tests/`, `benches/` and `Cargo.*` | `docs/finder.md` |

The very first run (`trig_012ER29uuypTqhUEnHtyZfrF`, 2026-11-18T23:30:00Z) was a single session that took both roles, before they were separated.

## Open failing cases

Both roles decide what to do from the open failing cases: cases under `cases/stage<N>/` for every stage up to the one in `status/stage.txt` that are not listed in `status/passing.txt`, are not stuck, and have no `claude/fix-` branch on origin yet. A case is stuck when `status/attempts.tsv` has three or more rows for its branch name (`claude/fix-<stage>-<case>`).

## A Fixer run

Up to three iterations. Each one:

1. `git fetch --prune origin` and start from a fresh `origin/main`.
2. If there is no open failing case, stop.
3. Fix one case as `docs/fixer.md` says and push the branch.
4. Wait for the judge: poll `git ls-remote origin` every 30 seconds for up to 15 minutes until the branch is gone (merged) or `status/attempts.tsv` on origin/main has a new row for it (rejected).

## A Finder run

One iteration:

1. `git fetch --prune origin` and start from a fresh `origin/main`.
2. If there are three or more open failing cases, stop: the Fixer has enough work.
3. Add cases as `docs/finder.md` says and push the branch.
4. Wait for the judge as the Fixer does.

## What you never do

- Push to main, merge a branch, or edit anything under `status/`. Only the judge does that.
- Change `harness/`, `cases/` that already exist, `.github/`, `scripts/` or the documents. If one of them is in your way, stop and say so in your final message; a human decides.
- Change `status/stage.txt`. Moving to the next stage is a human decision.

## Running commands

Run every build and comparison through `scripts/run.sh`, for example:

```
scripts/run.sh cargo build --release
scripts/run.sh python3 harness/compare.py cases/stage1/static-file --out results/static-file.json
```

`results/*.json` holds, for each request, what nginx answered (`nginx`), what twinx answered (`twinx`) and the differences (`problems`).
