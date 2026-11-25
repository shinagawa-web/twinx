#!/usr/bin/env python3
"""Measure what share of twinx's code its own unit tests (cargo test) run.

Reads an LCOV file exported from the profiles cargo test wrote, and counts,
over every file under src/, the instrumented lines and those the tests ran.
Lines inside #[cfg(test)] modules are the tests themselves and are left out.
Recorded next to the nginx-tests coverage, not judged.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def test_module_lines(text):
    """Line numbers inside `#[cfg(test)] mod name { ... }` blocks."""
    lines, out = text.splitlines(), set()
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("#[cfg(test)]"):
            j = i + 1
            while j < len(lines) and not re.match(r"\s*(pub\s+)?mod\s+\w+\s*\{", lines[j]):
                if lines[j].strip() and not lines[j].strip().startswith("#["):
                    break
                j += 1
            if j < len(lines) and re.match(r"\s*(pub\s+)?mod\s+\w+\s*\{", lines[j]):
                depth, k = 0, j
                while k < len(lines):
                    code = re.sub(r'"(\\.|[^"\\])*"|//.*', "", lines[k])
                    depth += code.count("{") - code.count("}")
                    out.add(k + 1)
                    if depth <= 0 and k > j:
                        break
                    k += 1
                out.update(range(i + 1, j + 1))
                i = k
        i += 1
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lcov", required=True, help="LCOV exported from cargo test's profiles")
    parser.add_argument("--tree", required=True, help="the source tree the tests were built from")
    parser.add_argument("--seconds", type=int, help="how long cargo test took")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    counts, path = {}, None
    for line in Path(args.lcov).read_text().splitlines():
        if line.startswith("SF:"):
            source = line[3:]
            index = source.rfind("/src/")
            path = source[index + 1:] if index >= 0 else None
        elif line.startswith("DA:") and path:
            number, count = line[3:].split(",")[:2]
            file = counts.setdefault(path, {})
            file[int(number)] = max(file.get(int(number), 0), int(count))

    total = covered = 0
    for path, lines in counts.items():
        source = Path(args.tree) / path
        skip = test_module_lines(source.read_text()) if source.exists() else set()
        for number, count in lines.items():
            if number in skip:
                continue
            total += 1
            covered += count > 0
    result = {"lines": total, "covered": covered,
              "percent": round(100.0 * covered / total, 2) if total else None,
              "seconds": args.seconds}
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
