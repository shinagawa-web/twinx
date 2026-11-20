#!/usr/bin/env python3
"""Measure how much of the code a branch adds is run by nginx-tests.

Reads an LCOV file exported from the profiles twinx wrote while every case
ran against it, and the lines added under src/ since a base commit (the
working tree is main with the branch merged in). Only lines the compiler
instrumented count: comments, blank lines and #[cfg(test)] code have no
coverage record and are left out.
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


def added_lines(base):
    out = subprocess.run(
        ["git", "diff", "-U0", "--no-renames", base, "--", "src"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    lines, path = {}, None
    for line in out.splitlines():
        if line.startswith("+++ "):
            path = None if line[4:] == "/dev/null" else line[6:]
        elif line.startswith("@@") and path:
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            start, count = int(match.group(1)), int(match.group(2) or 1)
            lines.setdefault(path, set()).update(range(start, start + count))
    return lines


def line_counts(lcov):
    counts, path = {}, None
    for line in Path(lcov).read_text().splitlines():
        if line.startswith("SF:"):
            # Profiles may come from another checkout of the repository (the VM, a runner),
            # so the path is taken from its src/ component on.
            source = line[3:]
            index = source.rfind("/src/")
            path = source[index + 1:] if index >= 0 else None
        elif line.startswith("DA:") and path:
            number, count = line[3:].split(",")[:2]
            counts.setdefault(path, {})[int(number)] = int(count)
    return counts


def ranges(numbers):
    numbers, out = sorted(numbers), []
    for n in numbers:
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return [f"{a}" if a == b else f"{a}-{b}" for a, b in out]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True)
    parser.add_argument("--lcov", help="LCOV exported from the nginx-tests runs; missing means nothing ran")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    added = added_lines(args.base)
    have_profiles = bool(args.lcov) and Path(args.lcov).exists()
    counts = line_counts(args.lcov) if have_profiles else {}
    executable, missed = 0, {}
    for path, numbers in sorted(added.items()):
        if not have_profiles:
            # twinx never ran: every added line counts as missed.
            executable += len(numbers)
            missed.setdefault(path, set()).update(numbers)
            continue
        # The coverage map lists every instrumented function whether it ran or not,
        # so a file with no record has no executable code in the binary.
        file_counts = counts.get(path, {})
        for n in numbers:
            if n in file_counts:
                executable += 1
                if file_counts[n] == 0:
                    missed.setdefault(path, set()).add(n)
    covered = executable - sum(len(v) for v in missed.values())
    result = {
        "added_executable_lines": executable,
        "covered_by_cases": covered,
        "percent": round(100.0 * covered / executable, 2) if executable else None,
        "missed": {path: ranges(numbers) for path, numbers in sorted(missed.items())},
    }
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
