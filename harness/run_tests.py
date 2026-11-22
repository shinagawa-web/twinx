#!/usr/bin/env python3
"""Run nginx-tests against twinx, or against nginx itself, and record every subtest.

Each test file runs in its own container from harness/nginx-tests/Dockerfile:
no network but loopback, an unprivileged user, a read-only filesystem except
/tmp, and twinx mounted read-only. The TAP comes back on the container's
standard output, which the server under test cannot write to (tap.pl).

  run_tests.py --twinx target/release/twinx --out results/all.json
  run_tests.py --nginx --out results/nginx.json
  run_tests.py --twinx target/release/twinx rewrite.t index.t
  run_tests.py --twinx target/release/twinx --reference results/nginx.json

With --reference, each file is also reported as passing or failing: it fails
when a subtest that passes on nginx does not pass on twinx.

Exit status: 0 when it ran, 2 when it could not (no Docker, unknown file).
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import uuid
from pathlib import Path

HARNESS = Path(__file__).resolve().parent
REPO = Path(os.environ.get("TWINX_REPO") or HARNESS.parent).resolve()
TESTS_DIR = HARNESS / "nginx-tests"

# The image twinx is built in by the judge (rust:1.100-slim-bookworm).
RUST_IMAGE = "rust@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37"

# Where the nginx-tests images are published, under the tag image() gives them.
REGISTRY = "ghcr.io/shinagawa-web"

NGINX_BINARY = "/usr/sbin/nginx"
TWINX_BINARY = "/usr/local/bin/twinx"
TIMEOUT = 300

PLAN = re.compile(r"^1\.\.(\d+)(?:\s*#\s*skip\S*\s*(.*))?$", re.IGNORECASE)
RESULT = re.compile(r"^(not )?ok (\d+)\b(.*)$")
SKIP = re.compile(r"#\s*skip", re.IGNORECASE)


def image(target):
    """The tag of an nginx-tests image ("nginx" or "twinx"), named after what it is built from."""
    digest = hashlib.sha256()
    for path in sorted(p for p in TESTS_DIR.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(TESTS_DIR)).encode() + b"\0" + path.read_bytes())
    return f"twinx-nginx-tests:{digest.hexdigest()[:12]}-{target}"


def image_arch(tag):
    out = subprocess.run(["docker", "image", "inspect", "-f", "{{.Architecture}}", tag], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else None


def build_image(target):
    """Make the image available for this machine: already here, pulled from REGISTRY, or built."""
    tag = image(target)
    arch = subprocess.run(["docker", "version", "-f", "{{.Server.Arch}}"], capture_output=True, text=True).stdout.strip()
    if image_arch(tag) == arch:
        return tag
    # .github/workflows/nginx-tests-image.yml pushes every image main builds, so a machine
    # whose containers cannot reach apt or GitHub can still run the tests. Docker may pull
    # an image built for another architecture with only a warning, so check what came.
    published = f"{REGISTRY}/{tag}"
    if subprocess.run(["docker", "pull", "-q", "--platform", f"linux/{arch}", published], capture_output=True).returncode == 0:
        if image_arch(published) == arch:
            subprocess.run(["docker", "tag", published, tag], check=True)
            return tag
        subprocess.run(["docker", "rmi", "-f", published], capture_output=True)
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)
    subprocess.run(["docker", "build", "-q", "--target", target, "-t", tag, str(TESTS_DIR)],
                   check=True, stdout=subprocess.DEVNULL)
    return tag


def stage_files(stage):
    stages = tomllib.loads((HARNESS / "stages.toml").read_text())
    files = []
    for n in range(1, stage + 1):
        files += stages.get(f"stage{n}", {}).get("files", [])
    return files


def parse_tap(text):
    """Subtest number -> "ok", "not ok" or "skip", the plan, and a whole-file skip."""
    tests, planned, skip_all = {}, None, None
    for line in text.splitlines():
        if match := PLAN.match(line):
            planned = int(match.group(1))
            if planned == 0:
                skip_all = match.group(2) or "skipped"
        elif match := RESULT.match(line):
            number = match.group(2)
            if SKIP.search(match.group(3)):
                tests[number] = "skip"
            else:
                tests[number] = "not ok" if match.group(1) else "ok"
    return tests, planned, skip_all


def run_file(tag, name, binary, profiles):
    container = f"twinx-test-{uuid.uuid4().hex[:12]}"
    command = [
        "docker", "run", "--rm", "--name", container, "--network", "none",
        "--user", "65534:65534", "--read-only", "--tmpfs", "/tmp:rw,exec,size=512m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "512", "--memory", "2g", "-e", "HOME=/tmp", "-w", "/nginx-tests",
    ]
    if binary is None:
        command += ["-e", f"TEST_NGINX_BINARY={NGINX_BINARY}"]
    else:
        command += ["-v", f"{binary}:{TWINX_BINARY}:ro", "-e", f"TEST_NGINX_BINARY={TWINX_BINARY}"]
    if profiles:
        stem = name.removesuffix(".t")
        command += ["-v", f"{profiles}:/profiles", "-e", f"LLVM_PROFILE_FILE=/profiles/{stem}-%p-%c.profraw"]
    command += [tag, "timeout", str(TIMEOUT), "perl", "tap.pl", name]
    started = time.monotonic()
    try:
        done = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=TIMEOUT + 30)
        stdout, stderr, status = done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired as expired:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        stdout, stderr, status = expired.stdout or "", expired.stderr or "", None
        stdout = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
        stderr = stderr if isinstance(stderr, str) else stderr.decode(errors="replace")
    tests, planned, skip_all = parse_tap(stdout)
    return {
        "file": name,
        "planned": planned,
        "skip_all": skip_all,
        "tests": tests,
        "exit": status,
        "seconds": round(time.monotonic() - started, 1),
        "stderr": stderr[-4000:],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--twinx", help="the twinx binary to test")
    target.add_argument("--nginx", action="store_true", help="test the reference nginx instead")
    parser.add_argument("files", nargs="*", help="test files (default: every file up to the current stage)")
    parser.add_argument("--stage", type=int, help="the stage whose files to run (default: status/stage.txt)")
    parser.add_argument("--out", help="write the results as JSON to this file")
    parser.add_argument("--profiles", help="a directory twinx writes coverage profiles to")
    parser.add_argument("--reference", help="results for nginx to compare with (from --nginx --out)")
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()

    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("harness: cannot reach the Docker daemon", file=sys.stderr)
        return 2
    stage = args.stage or int((REPO / "status" / "stage.txt").read_text().strip())
    known = stage_files(stage)
    files = args.files or known
    unknown = [f for f in files if f not in known]
    if unknown:
        print(f"harness: not in stages 1-{stage}: {unknown}", file=sys.stderr)
        return 2

    binary = None
    if args.twinx:
        binary = Path(args.twinx).resolve()
    tag = build_image("nginx" if binary is None else "twinx")
    profiles = str(Path(args.profiles).resolve()) if args.profiles else None
    started = time.monotonic()
    if binary is not None and not binary.is_file():
        results = [{"file": f, "planned": None, "skip_all": None, "tests": {}, "exit": None,
                    "seconds": 0, "stderr": f"twinx binary not found at {binary}"} for f in files]
    else:
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            results = list(pool.map(lambda f: run_file(tag, f, binary, profiles), files))

    reference = json.loads(Path(args.reference).read_text())["files"] if args.reference else None
    for r in results:
        oks = {n for n, s in r["tests"].items() if s == "ok"}
        state = f"skipped ({r['skip_all']})" if r["skip_all"] else f"{len(oks)} of {r['planned'] or len(r['tests'])} ok"
        if reference is not None and r["file"] in reference:
            expected = {n for n, s in reference[r["file"]]["tests"].items() if s == "ok"}
            if expected:
                missing = sorted(expected - oks, key=int)
                state = "PASS" if not missing else f"FAIL, not ok: {', '.join(missing)}"
            else:
                state = "not expected (nginx passes no subtest here)"
        print(f"{r['file']}: {state}")
    summary = {
        "target": "nginx" if binary is None else "twinx",
        "image": tag,
        "stage": stage,
        "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 1),
        "files": len(results),
    }
    if args.out:
        Path(args.out).write_text(json.dumps({"summary": summary, "files": {r["file"]: r for r in results}}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
