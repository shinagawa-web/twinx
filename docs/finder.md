# Finder

Add cases that cover behavior of the current stage (`status/stage.txt`, scope in README.md) that no existing case covers yet.

## What a case is

A directory `cases/stage<N>/<name>/` with:

- `case.toml`: a `description`, a `config` (what goes inside the `http` block) and one or more `[[requests]]` with a `raw` HTTP request. See the existing cases for the format.
- `files/` (optional): the document root, used through `{{root}}`.

Placeholders in `config`: `{{port}}` (listen port), `{{root}}` (document root), `{{dir}}` (the case's working directory) and `{{backend}}` (an upstream that answers with the exact request it received).

## What makes a good case

- It is how people configure nginx in practice: patterns from nginx's documentation and from real deployments, including their edge cases (trailing slashes, query strings, missing files, location precedence).
- It checks one behavior, with one to six requests that show it.
- Every request sends `Connection: close`.
- The answer does not depend on time or on anything outside the case.

## How to add cases

1. Read the existing cases so you do not repeat one.
2. Write up to five new cases.
3. Run them (`scripts/run.sh python3 harness/compare.py cases/stage<N>/<name> --out results/<name>.json`) and check in the results that nginx started and answered as the case intends. A case whose configuration nginx refuses is only useful when the refusal is the behavior being checked.
4. Push them on one branch, `claude/find-<short-name>`, adding files under `cases/` only. Existing cases may not be changed; the judge rejects that.
