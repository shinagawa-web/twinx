# One run of the loop

Both scheduled runs are paused since 2026-11-19T00:07Z, until the design is ready for unattended runs.

Two scheduled Claude Code sessions run the loop, both with model `claude-opus-5-5`. Each session has one role and never takes the other, so the Finder writes cases without knowing how twinx is written.

| Role | Routine | Schedule | Rules |
|---|---|---|---|
| Fixer | `trig_01YX3pTLi2c3KYXT33CabyPp` | every hour at :30 (cron `30 * * * *`) | `docs/fixer.md` |
| Finder | `trig_01GqFt2a2yGPCmAoq9UnXr3y` | every hour at :49 (cron `49 * * * *`); its checkout leaves out `src/`, `tests/`, `benches/` and `Cargo.*` | `docs/finder.md` |

The very first run (`trig_012ER29uuypTqhUEnHtyZfrF`, 2026-11-18T23:30:00Z) was a single session that took both roles, before they were separated.

## Pull requests

Every change reaches main through a pull request that the `judge` check passes. Open it through the REST API (`gh pr` subcommands that use GraphQL do not work in a cloud session) and turn on auto-merge in the same step, so it merges as soon as the judge passes:

```
gh api repos/shinagawa-web/twinx/pulls -f title="<what it does>" -f head=<branch> -f base=main -f body="<why>"
gh api graphql -f query='mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:SQUASH}){clientMutationId}}' -f id=<node_id from the response>
```

If GraphQL is refused, leave auto-merge off and merge through REST once the check passes: `gh api -X PUT repos/shinagawa-web/twinx/pulls/<number>/merge -f merge_method=squash`.

Then wait: every 30 seconds, for up to 20 minutes, read the pull request (`gh api repos/shinagawa-web/twinx/pulls/<number>`). It is done when `merged` is true. When the judge fails it comments the reasons on the pull request (`gh api repos/shinagawa-web/twinx/issues/<number>/comments`); read them, then close the pull request (`gh api -X PATCH repos/shinagawa-web/twinx/pulls/<number> -f state=closed`). When main moved and the branch is behind, update it (`gh api -X PUT repos/shinagawa-web/twinx/pulls/<number>/update-branch`) and keep waiting.

## Open failing cases

The cases that fail on main are listed in the judge's comment on the most recently merged pull request (the "Failing:" line). A Fixer can also find them by building twinx and running every case.

An open failing case is one under `cases/stage<N>/`, for every stage up to the one in `status/stage.txt`, that fails on main, is not stuck, and has no open pull request yet. A case is stuck when three pull requests from its branch (`claude/fix-<stage>-<case>`) were closed without being merged (`gh api "repos/shinagawa-web/twinx/pulls?state=closed&head=shinagawa-web:claude/fix-<stage>-<case>"`, counting those with `merged_at` null).

## A Fixer run

Up to three iterations. Each one:

1. `git fetch --prune origin` and start from a fresh `origin/main`.
2. If there is no open failing case, stop.
3. Fix one case as `docs/fixer.md` says, open the pull request and wait for it as above.

## A Finder run

One iteration:

1. `git fetch --prune origin` and start from a fresh `origin/main`.
2. If there are three or more open failing cases, stop: the Fixer has enough work.
3. Add cases as `docs/finder.md` says, open the pull request and wait for it as above.

## What you never do

- Push to main. The ruleset refuses it anyway; every change goes through a pull request.
- Merge a pull request whose `judge` check has not passed, or one that is not yours.
- Change `harness/`, `cases/` that already exist, `.github/`, `scripts/`, `status/` or the documents. If one of them is in your way, stop and say so in your final message; a human decides.

## Running commands

Run every build and comparison through `scripts/run.sh`, for example:

```
scripts/run.sh cargo build --release
scripts/run.sh python3 harness/compare.py cases/stage1/static-file --out results/static-file.json
```

`results/*.json` holds, for each request, what nginx answered (`nginx`), what twinx answered (`twinx`) and the differences (`problems`).
