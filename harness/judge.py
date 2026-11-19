#!/usr/bin/env python3
"""Decide whether a pull request into main passes the judge.

Run from a checkout of main with the pull request merged but not
committed, after every case has run twice: against main as it is (the
baseline) and against the merged tree. The branch name says what the pull
request is for:

  claude/fix-<stage>-<case>   a Fixer change that makes cases/<stage>/<case> pass
  claude/find-<anything>      a Finder change that adds new cases
  anything else               a change by a human

Every pull request must build, pass cargo test and keep every case that
passes on main passing. A Fixer pull request may only touch twinx's code,
must make the case it names pass, and the cases must run at least 99% of
the executable lines it adds. A Finder pull request may only add files
under cases/. Cases that fail on main are allowed: they are the Fixer's
work queue, so a green check means main did not get worse, not that every
case passes.

Exit status 0 means the pull request passes. The verdict is written as
JSON and as Markdown for the pull request comment.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# The repository the scripts work on. The judge runs copies of these scripts taken from
# main before the pull request is merged, so a pull request cannot change how it is judged.
REPO = Path(os.environ.get("TWINX_REPO") or Path(__file__).resolve().parent.parent).resolve()

# Share of the executable lines a Fixer pull request adds that the cases must run.
COVERAGE_THRESHOLD = 99.0

FIXER_MAY_TOUCH = ("src/", "tests/", "benches/", "Cargo.toml", "Cargo.lock")
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
    if branch.startswith("claude/"):
        return None, None
    return "human", None


def path_problems(role, changes):
    problems = []
    for status, path in changes:
        if role == "fix" and not path.startswith(FIXER_MAY_TOUCH):
            problems.append(f"a Fixer pull request may not touch {path}")
        if role == "find":
            if not path.startswith(FINDER_MAY_ADD):
                problems.append(f"a Finder pull request may not touch {path}")
            elif status != "A":
                problems.append(f"a Finder pull request may only add files, but {path} is {status}")
    return problems


def passing(results_file):
    if not results_file or not Path(results_file).exists():
        return []
    return sorted(r["case"] for r in json.loads(Path(results_file).read_text())["results"] if r["passed"])


def markdown(verdict):
    lines = [f"## judge: {'pass' if verdict['passed'] else 'fail'}", ""]
    if verdict["problems"]:
        lines += ["Problems:", ""] + [f"- {p}" for p in verdict["problems"]] + [""]
    lines += [
        f"- Role: {verdict['role'] or 'unknown'}" + (f", target `{verdict['target']}`" if verdict["target"] else ""),
        f"- Cases passing on main: {verdict['cases_passing_before']}; with this pull request: "
        f"{verdict['cases_passing_after']} of {verdict['cases']}",
    ]
    if verdict["newly_passing"]:
        lines.append("- Newly passing: " + ", ".join(f"`{c}`" for c in verdict["newly_passing"]))
    # The Finder cannot build twinx, so it reads which cases fail from this line.
    lines.append("- Failing: " + (", ".join(f"`{c}`" for c in verdict["failing"]) or "none"))
    coverage = verdict.get("coverage")
    if coverage and coverage.get("percent") is not None:
        lines.append(f"- Added executable lines run by the cases: {coverage['covered_by_cases']} of "
                     f"{coverage['added_executable_lines']} ({coverage['percent']}%)")
    lines += ["", f"main `{verdict['base'][:7]}`, pull request head `{verdict['head'][:7]}`"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--branch", required=True)
    parser.add_argument("--base", required=True, help="the main commit the pull request is judged against")
    parser.add_argument("--head", required=True, help="the pull request head commit")
    parser.add_argument("--build", required=True, choices=["success", "failure", "skipped"])
    parser.add_argument("--test", required=True, choices=["success", "failure", "skipped"])
    parser.add_argument("--baseline", help="JSON written by compare.py for main as it is")
    parser.add_argument("--results", help="JSON written by compare.py for the merged tree")
    parser.add_argument("--coverage", help="JSON written by coverage.py")
    parser.add_argument("--verdict", required=True, help="where to write the verdict JSON")
    parser.add_argument("--comment", required=True, help="where to write the Markdown comment")
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

    if not args.results or not Path(args.results).exists():
        problems.append("the cases did not run")
        results = []
    else:
        results = json.loads(Path(args.results).read_text())["results"]
    passing_now = sorted(r["case"] for r in results if r["passed"])
    passing_before = passing(args.baseline)
    known = {r["case"] for r in results}
    regressed = [c for c in passing_before if c in known and c not in passing_now]
    if regressed:
        problems.append(f"cases that pass on main no longer pass: {regressed}")
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
                f"this pull request adds, below {COVERAGE_THRESHOLD}%; not run by any case: {missed}"
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
        "failing": sorted(known - set(passing_now)),
        "coverage": coverage,
    }
    Path(args.verdict).write_text(json.dumps(verdict, indent=2))
    Path(args.comment).write_text(markdown(verdict))
    print(json.dumps(verdict, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
