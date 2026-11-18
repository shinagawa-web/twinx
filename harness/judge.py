#!/usr/bin/env python3
"""Decide whether a claude/ branch may be merged into main.

Run from a checkout of main with the branch merged but not committed. The
branch name says what the branch is for:

  claude/fix-<stage>-<case>   a Fixer change that makes cases/<stage>/<case> pass
  claude/find-<anything>      a Finder change that adds new cases

A branch passes when it only touches the files its role may touch, the
build and cargo test succeed, no case that passes on main stops passing,
and, for a Fixer branch, the case it names passes.

Exit status 0 means merge. The verdict is also written as JSON.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# The repository the scripts work on. The judge runs copies of these scripts taken from
# main before the branch is merged, so a branch cannot change how it is judged.
REPO = Path(os.environ.get("TWINX_REPO") or Path(__file__).resolve().parent.parent).resolve()
PASSING = REPO / "status" / "passing.txt"

# Share of the executable lines a Fixer branch adds that the cases must run.
COVERAGE_THRESHOLD = 99.0

FIXER_MAY_TOUCH =("src/", "tests/", "benches/", "Cargo.toml", "Cargo.lock")
FINDER_MAY_ADD = ("cases/",)


def changed_files(base, head):
    out = subprocess.run(
        ["git", "diff", "--name-status", "--no-renames", f"{base}...{head}"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    return [line.split("\t", 1) for line in out.splitlines() if line]


def role_of(branch):
    match = re.fullmatch(r"claude/fix-(stage\d+)-(.+)", branch)
    if match:
        return "fix", f"cases/{match.group(1)}/{match.group(2)}"
    if re.fullmatch(r"claude/find-.+", branch):
        return "find", None
    return None, None


def path_problems(role, changes):
    problems = []
    for status, path in changes:
        if role == "fix" and not path.startswith(FIXER_MAY_TOUCH):
            problems.append(f"a Fixer branch may not touch {path}")
        if role == "find":
            if not path.startswith(FINDER_MAY_ADD):
                problems.append(f"a Finder branch may not touch {path}")
            elif status != "A":
                problems.append(f"a Finder branch may only add files, but {path} is {status}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--branch", required=True)
    parser.add_argument("--base", required=True, help="the main commit the branch is judged against")
    parser.add_argument("--head", required=True, help="the branch commit")
    parser.add_argument("--build", required=True, choices=["success", "failure", "skipped"])
    parser.add_argument("--test", required=True, choices=["success", "failure", "skipped"])
    parser.add_argument("--results", required=True, help="JSON written by compare.py")
    parser.add_argument("--coverage", help="JSON written by coverage.py")
    parser.add_argument("--verdict", required=True, help="where to write the verdict JSON")
    args = parser.parse_args()

    role, target = role_of(args.branch)
    problems = []
    if role is None:
        problems.append(f"{args.branch} is neither claude/fix-<stage>-<case> nor claude/find-<name>")
    else:
        problems += path_problems(role, changed_files(args.base, args.head))
    if args.build == "failure":
        problems.append("cargo build failed")
    if args.test == "failure":
        problems.append("cargo test failed")

    results = json.loads(Path(args.results).read_text())["results"]
    passing_now = sorted(r["case"] for r in results if r["passed"])
    passing_before = PASSING.read_text().split() if PASSING.exists() else []
    known = {r["case"] for r in results}
    regressed = [c for c in passing_before if c in known and c not in passing_now]
    if regressed:
        problems.append(f"cases that passed on main no longer pass: {regressed}")
    if role == "fix":
        if target not in known:
            problems.append(f"{target} does not exist")
        elif target not in passing_now:
            problems.append(f"{target} still does not pass")

    coverage = json.loads(Path(args.coverage).read_text()) if args.coverage and Path(args.coverage).exists() else None
    if role == "fix":
        if coverage is None:
            problems.append("no coverage was measured")
        elif coverage["percent"] is not None and coverage["percent"] < COVERAGE_THRESHOLD:
            missed = "; ".join(f"{path}:{','.join(lines)}" for path, lines in coverage["missed"].items())
            problems.append(
                f"the cases run {coverage['percent']}% of the {coverage['added_executable_lines']} lines "
                f"this branch adds, below {COVERAGE_THRESHOLD}%; not run by any case: {missed}"
            )

    verdict = {
        "branch": args.branch,
        "role": role,
        "target": target,
        "base": args.base,
        "head": args.head,
        "passed": not problems,
        "problems": problems,
        "cases": len(results),
        "cases_passing_before": len(passing_before),
        "cases_passing_after": len(passing_now),
        "newly_passing": [c for c in passing_now if c not in passing_before],
        "coverage": coverage,
    }
    Path(args.verdict).write_text(json.dumps(verdict, indent=2))
    if not problems:
        PASSING.parent.mkdir(exist_ok=True)
        PASSING.write_text("".join(c + "\n" for c in passing_now))
    print(json.dumps(verdict, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
