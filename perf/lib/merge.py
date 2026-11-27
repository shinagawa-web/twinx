"""Puts the measurements of the groups of scenarios, made in jobs of their own, in one file.

    python3 perf/lib/merge.py <out.json> <group.json>...
"""

import json
import re
import sys

from scenarios import SCENARIOS


def main(out, paths):
    parts = [json.load(open(p)) for p in paths]
    order = [q["name"] for q in SCENARIOS]
    # Every scenario that the parts were asked for, so that a job that lost some shows.
    wanted = {q["name"] for q in SCENARIOS for p in parts
              if p["group"] in (None, q["group"]) and (not p.get("only") or re.search(p["only"], q["name"]))
              and (not p.get("names") or q["name"] in p["names"])}
    merged = {**parts[0], "group": None}
    merged["scenarios"] = sorted((s for p in parts for s in p["scenarios"]), key=lambda s: order.index(s["name"]))
    missing = wanted - {s["name"] for s in merged["scenarios"]}
    if missing:
        raise SystemExit("not among the measurements: " + ", ".join(sorted(missing)))
    # A part of named scenarios has no group.
    merged["machines"] = {p["group"] or "scenarios": p["machine"] for p in parts}
    for key, empty in (("panics", []), ("restarts", 0)):
        merged[key] = {n: sum((p[key][n] for p in parts), empty) for n in merged["servers"]}
    with open(out, "w") as f:
        json.dump(merged, f, indent=1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
