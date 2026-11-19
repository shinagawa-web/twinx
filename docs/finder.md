# Finder

Add cases for the items of the current stage (`status/stage.txt`) in `harness/checklist.toml` that no passing case covers yet. The judge lists them on the "checklist" line of its comment on the most recently merged pull request.

Write cases from what nginx does, not from what twinx does. Do not read twinx's code (`src/`, `tests/`, `benches/`, `Cargo.toml`), its commits or its diffs, and do not build or run twinx. When you run a case, only the `nginx` side of the results matters; the `twinx` side reports that the binary is missing, and that is expected.

## What a case is

A directory `cases/stage<N>/<name>/` with:

- `case.toml`: a `description`, `covers` (the checklist items the case shows), a `config` (what goes inside the `http` block) and one or more `[[requests]]` with a `raw` HTTP request. See the existing cases for the format.
- `files/` (optional): the document root, used through `{{root}}`.

Placeholders in `config`: `{{port}}` (listen port), `{{root}}` (document root), `{{dir}}` (the case's working directory) and `{{backend}}` (an upstream that answers with the exact request it received).

## What makes a good case

- It is how people configure nginx in practice: patterns from nginx's documentation and from real deployments, including their edge cases (trailing slashes, query strings, missing files, location precedence).
- It checks one behavior, with one to six requests that show it.
- Every request sends `Connection: close`.
- The answer does not depend on time or on anything outside the case.

## How to add cases

1. Take the items not covered yet from the judge's checklist line, and read the existing cases so you do not repeat one.
2. Write up to five new cases for them. Every case names at least one item in `covers`; the judge rejects a case without one or with an item not in the checklist.
3. Run them (`scripts/run.sh python3 harness/compare.py cases/stage<N>/<name> --out results/<name>.json`) and check in the results that nginx started and answered as the case intends. A case whose configuration nginx refuses is only useful when the refusal is the behavior being checked.
4. Open one pull request for them from the branch `claude/find-<short-name>`, adding files under `cases/` only. Existing cases may not be changed; the judge rejects that.
