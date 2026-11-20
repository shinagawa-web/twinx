#!/usr/bin/env python3
"""Decide whether a pull request into main passes the judge.

Run from a checkout of main with the pull request merged but not
committed, after nginx-tests ran three times (harness/run_tests.py):
against nginx 1.30.6 (the reference), against twinx built from main (the
baseline) and against twinx built from the merged tree. Only a subtest
that passes on nginx is expected of twinx; a file passes when twinx passes
every subtest of it that nginx passes. The branch name says what the pull
request is for:

  claude/fix-<stage>-<file>   a Fixer change that makes <file>.t pass
  anything not under claude/  a change by a human

Every pull request must build, pass cargo test and keep every expected
subtest that passes on main passing. A Fixer pull request may only touch
twinx's code, must make the file it names pass, and nginx-tests must run
at least 99% of the executable lines it adds. Files that fail on main are
allowed: they are the Fixer's work queue, so a green check means main did
not get worse, not that every file passes.

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

# Share of the executable lines a Fixer pull request adds that nginx-tests must run.
COVERAGE_THRESHOLD = 99.0

FIXER_MAY_TOUCH = ("src/", "tests/", "benches/", "Cargo.toml", "Cargo.lock")


def changed_files(base, head):
    out = subprocess.run(
        ["git", "diff", "--name-status", "--no-renames", f"{base}...{head}"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    return [line.split("\t", 1) for line in out.splitlines() if line]


def role_of(branch):
    match = re.fullmatch(r"claude/fix-(stage\d+)-(.+)", branch)
    if match:
        return "fix", f"{match.group(2)}.t"
    if branch.startswith("claude/"):
        return None, None
    return "human", None


def load(path):
    if not path or not Path(path).exists():
        return None
    return json.loads(Path(path).read_text())["files"]


def passing(results, name):
    file = (results or {}).get(name)
    return {n for n, s in file["tests"].items() if s == "ok"} if file else set()


def markdown(verdict):
    lines = [f"## judge: {'pass' if verdict['passed'] else 'fail'}", ""]
    if verdict["problems"]:
        lines += ["Problems:", ""] + [f"- {p}" for p in verdict["problems"]] + [""]
    lines += [
        f"- Role: {verdict['role'] or 'unknown'}" + (f", target `{verdict['target']}`" if verdict["target"] else ""),
        f"- nginx-tests files passing on main: {verdict['files_passing_before']}; with this pull request: "
        f"{verdict['files_passing_after']} of {verdict['files']} "
        f"({verdict['subtests_passing_after']} of {verdict['subtests']} subtests)",
    ]
    if verdict["newly_passing"]:
        lines.append("- Newly passing: " + ", ".join(f"`{f}`" for f in verdict["newly_passing"]))
    lines.append("- Failing: " + (", ".join(f"`{f}`" for f in verdict["failing"]) or "none"))
    coverage = verdict.get("coverage")
    if coverage and coverage.get("percent") is not None:
        lines.append(f"- Added executable lines run by nginx-tests: {coverage['covered_by_cases']} of "
                     f"{coverage['added_executable_lines']} ({coverage['percent']}%)")
    if coverage and coverage.get("regions_percent") is not None:
        # Recorded, not judged (#12): a line counts as run when any region on it ran.
        lines.append(f"- Added code regions run by nginx-tests (recorded, not judged): {coverage['regions_run']} of "
                     f"{coverage['added_regions']} ({coverage['regions_percent']}%)"
                     + (f"; not run: {', '.join(coverage['regions_not_run'][:20])}" if coverage["regions_not_run"] else ""))
    lines += ["", f"main `{verdict['base'][:7]}`, pull request head `{verdict['head'][:7]}`"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--branch", required=True)
    parser.add_argument("--base", required=True, help="the main commit the pull request is judged against")
    parser.add_argument("--head", required=True, help="the pull request head commit")
    parser.add_argument("--build", required=True, choices=["success", "failure", "skipped"])
    parser.add_argument("--test", required=True, choices=["success", "failure", "skipped"])
    parser.add_argument("--reference", required=True, help="run_tests.py results for nginx")
    parser.add_argument("--baseline", help="run_tests.py results for twinx built from main")
    parser.add_argument("--results", help="run_tests.py results for twinx built from the merged tree")
    parser.add_argument("--coverage", help="JSON written by coverage.py")
    parser.add_argument("--verdict", required=True, help="where to write the verdict JSON")
    parser.add_argument("--comment", required=True, help="where to write the Markdown comment")
    args = parser.parse_args()

    role, target = role_of(args.branch)
    problems = []
    if role is None:
        problems.append(f"{args.branch} is neither claude/fix-<stage>-<file> nor a human branch")
    elif role == "fix":
        problems += [f"a Fixer pull request may not touch {path}"
                     for _, path in changed_files(args.base, args.head) if not path.startswith(FIXER_MAY_TOUCH)]
    if args.build == "failure":
        problems.append("cargo build failed")
    if args.test == "failure":
        problems.append("cargo test failed")

    reference = load(args.reference) or {}
    baseline = load(args.baseline)
    results = load(args.results)
    if results is None:
        problems.append("nginx-tests did not run")
        results = {}

    expected = {name: passing(reference, name) for name in reference}
    expected = {name: tests for name, tests in expected.items() if tests}
    regressed = []
    for name, tests in sorted(expected.items()):
        lost = sorted((tests & passing(baseline, name)) - passing(results, name), key=int)
        if lost:
            regressed.append(f"{name} ({', '.join(lost)})")
    if regressed:
        problems.append("subtests that pass on main no longer pass: " + "; ".join(regressed))

    def file_passes(run, name):
        return expected[name] <= passing(run, name)

    passing_before = [n for n in expected if baseline is not None and file_passes(baseline, n)]
    passing_after = [n for n in expected if file_passes(results, n)]
    if role == "fix":
        if target not in expected:
            problems.append(f"{target} is not an nginx-tests file that nginx passes in the current stages")
        elif target not in passing_after:
            missing = sorted(expected[target] - passing(results, target), key=int)
            problems.append(f"{target} still does not pass: subtests {', '.join(missing)}")

    coverage = json.loads(Path(args.coverage).read_text()) if args.coverage and Path(args.coverage).exists() else None
    if role == "fix":
        if coverage is None:
            problems.append("no coverage was measured")
        elif coverage["percent"] is not None and coverage["percent"] < COVERAGE_THRESHOLD:
            missed = "; ".join(f"{path}:{','.join(lines)}" for path, lines in coverage["missed"].items())
            problems.append(
                f"nginx-tests run {coverage['percent']}% of the {coverage['added_executable_lines']} lines "
                f"this pull request adds, below {COVERAGE_THRESHOLD}%; not run: {missed}"
            )

    verdict = {
        "branch": args.branch,
        "role": role,
        "target": target,
        "base": args.base,
        "head": args.head,
        "passed": not problems,
        "problems": problems,
        "files": len(expected),
        "files_passing_before": len(passing_before),
        "files_passing_after": len(passing_after),
        "subtests": sum(len(t) for t in expected.values()),
        "subtests_passing_after": sum(len(t & passing(results, n)) for n, t in expected.items()),
        "newly_passing": sorted(set(passing_after) - set(passing_before)),
        "failing": sorted(set(expected) - set(passing_after)),
        "coverage": coverage,
    }
    Path(args.verdict).write_text(json.dumps(verdict, indent=2))
    Path(args.comment).write_text(markdown(verdict))
    print(json.dumps(verdict, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
