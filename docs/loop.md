# One run of the loop

A scheduled Claude Code session runs this once an hour with model `claude-opus-5-5`. The first run is routine `trig_012ER29uuypTqhUEnHtyZfrF` at 2026-11-18T23:30:00Z, and the hourly runs are routine `trig_01YX3pTLi2c3KYXT33CabyPp` from 2026-11-19T00:30:00Z. Each run does up to three iterations and then ends.

## Each iteration

1. `git fetch --prune origin` and start from a fresh `origin/main`.
2. Choose a role:
   - Count the open failing cases: cases under `cases/stage<N>/` for every stage up to the one in `status/stage.txt` that are not listed in `status/passing.txt`, are not stuck, and have no `claude/fix-` branch on origin yet.
   - A case is stuck when `status/attempts.tsv` has three or more rows for its branch name (`claude/fix-<stage>-<case>`).
   - If there are fewer than three open failing cases, work as the Finder (`docs/finder.md`). Otherwise work as the Fixer (`docs/fixer.md`).
3. Push the branch your role produces, then wait for the judge: poll `git ls-remote origin` every 30 seconds for up to 15 minutes until the branch is gone (merged) or `status/attempts.tsv` on origin/main has a new row for it (rejected).
4. Start the next iteration from the new `origin/main`.

Stop early when every case up to the current stage passes and the Finder cannot think of a case that is not already covered, or when every failing case is stuck.

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
