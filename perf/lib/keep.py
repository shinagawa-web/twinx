"""Keeps nginx's measurements from a tag's run of all the scenarios, so that the other runs
measure twinx alone and are compared with them (bench.py --kept-nginx, compare.py --nginx).

    python3 perf/lib/keep.py perf/results/aarch64/v0.4.0.json perf/results/aarch64/nginx.json

nginx is the same nginx in every run; what moves between runners is ignored, as only the
scenarios far above nginx are worked on.
"""

import json
import sys

from scenarios import SCENARIOS


def main(path, out):
    run = json.load(open(path))
    if run.get("group") or run.get("only") or run.get("names"):
        raise SystemExit(f"{path} is not of all the scenarios")
    if any("nginx" not in s["servers"] for s in run["scenarios"]):
        raise SystemExit(f"{path} did not measure nginx in every scenario")
    kept = {
        "tag": run["tag"],
        "date": run["date"],
        "nginx": run["nginx"],
        "machine": run.get("machines") or run["machine"],
        "scenarios": {s["name"]: {**({"definition": s["definition"]} if "definition" in s else {}),
                                  "nginx": {k: v for k, v in s["servers"]["nginx"].items() if k != "runs"}}
                      for s in run["scenarios"]},
    }
    with open(out, "w") as f:
        json.dump(kept, f, indent=1)
    missing = [q["name"] for q in SCENARIOS if q["name"] not in kept["scenarios"]]
    if missing:
        print(f"not in {path}, so measured with nginx until a tag's run of all of them: " + "; ".join(missing))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
