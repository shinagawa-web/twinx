#!/usr/bin/env python3
"""Run test cases against nginx and twinx and compare the responses.

Each case is a directory holding a case.toml and, optionally, a files/
directory that becomes the document root. A case can set the mode of paths
under files/ with a `modes` table ("secret.txt" = "000"). Both servers read the same
rendered configuration, listen on the same port (one after the other, so
absolute redirects carry the same port) and serve the same files.

With --sandbox, twinx runs in a container as an unprivileged user, with the
case directory read-only and only /tmp writable, so it can reach nothing
of the machine running the harness: the judge uses this, because twinx is
the pull request's code.

Exit status: 0 when every request matches, 1 when any differs, 2 when the
harness itself cannot run (no Docker, no cases).
"""

import argparse
import datetime
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

NGINX_IMAGE = "nginx@sha256:42c68eab6f7e22611786a9fe1d1c019e275c50185bd54b8f75dc2b9184322703"
NGINX_VERSION = "1.30.6"
CONTAINER_NAME = "twinx-reference-nginx"
# The image the judge builds, tests and runs twinx in (rust:1.100-slim-bookworm).
SANDBOX_IMAGE = "rust@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37"
SANDBOX_NAME = "twinx-under-test"
SANDBOX_USER = "65534:65534"
PORT = 18080
BACKEND_PORT = 19090
WORK_ROOT = Path("/tmp/twinx-cases")
FIXED_MTIME = 1767225600  # 2026-01-01T00:00:00Z, so ETag and Last-Modified are stable
STARTUP_TIMEOUT = 5.0
REQUEST_TIMEOUT = 5.0

# Headers whose values legitimately differ between the two servers.
IGNORED_HEADERS = {"date", "server"}

# Each server names itself in the pages it generates ("<hr><center>nginx/1.30.6</center>").
# twinx names itself, not nginx, so both names are replaced before comparing.
SERVER_NAMES = re.compile(rb"nginx/1\.30\.6|twinx/[0-9][0-9A-Za-z.+-]*")
SERVER_PLACEHOLDER = b"<server>"

# The repository the scripts work on. The judge runs copies of these scripts taken from
# main before the branch is merged, so a branch cannot change how it is judged.
REPO = Path(os.environ.get("TWINX_REPO") or Path(__file__).resolve().parent.parent).resolve()
MIME_TYPES = Path(__file__).resolve().parent / "mime.types"

WRAPPER = """worker_processes 1;
pid /tmp/twinx-case.pid;
error_log stderr;
events {{ worker_connections 64; }}
http {{
    include {dir}/mime.types;
    default_type application/octet-stream;
    access_log off;
{config}
}}
"""


class EchoHandler(socketserver.BaseRequestHandler):
    """A backend for proxy cases: answers with the exact request it received."""

    def handle(self):
        self.request.settimeout(REQUEST_TIMEOUT)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value.strip())
            while len(body) < length:
                chunk = self.request.recv(65536)
                if not chunk:
                    break
                body += chunk
        except (socket.timeout, ValueError):
            pass
        echo = data
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + b"Content-Length: " + str(len(echo)).encode() + b"\r\n"
            + b"Connection: close\r\n\r\n" + echo
        )


class Backend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def wait_for_port(port, timeout, alive):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not alive():
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def send_raw(raw):
    data = b""
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=REQUEST_TIMEOUT) as sock:
            sock.sendall(raw)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
    except socket.timeout:
        data += b"<harness: timed out waiting for the connection to close>"
    except OSError as error:
        data += f"<harness: {error}>".encode()
    return data


def parse(response):
    head, sep, body = response.partition(b"\r\n\r\n")
    if not sep:
        return {"status": response.decode("latin-1"), "headers": [], "body": ""}
    lines = head.decode("latin-1").split("\r\n")
    normalized = SERVER_NAMES.sub(SERVER_PLACEHOLDER, body)
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        name, value = name.strip().lower(), value.strip()
        if name in IGNORED_HEADERS:
            continue
        # Replacing the server name changes the body length, so a Content-Length
        # that described the original body is recounted for the replaced one.
        if name == "content-length" and normalized != body and value == str(len(body)):
            value = str(len(normalized))
        headers.append([name, value])
    return {"status": lines[0], "headers": sorted(headers), "body": normalized.decode("latin-1")}


def diff(expected, actual):
    problems = []
    if expected["status"] != actual["status"]:
        problems.append(f"status: nginx {expected['status']!r}, twinx {actual['status']!r}")
    missing = [h for h in expected["headers"] if h not in actual["headers"]]
    extra = [h for h in actual["headers"] if h not in expected["headers"]]
    if missing:
        problems.append(f"headers only nginx sent: {missing}")
    if extra:
        problems.append(f"headers only twinx sent: {extra}")
    if expected["body"] != actual["body"]:
        problems.append(
            f"body: nginx {len(expected['body'])} bytes, twinx {len(actual['body'])} bytes; "
            f"nginx starts {expected['body'][:200]!r}, twinx starts {actual['body'][:200]!r}"
        )
    return problems


def make_writable(path):
    """Give the owner full access again, so a case that took it away can be removed."""
    for child in [path, *path.rglob("*")] if path.is_dir() else []:
        if not child.is_symlink():
            child.chmod(0o700 if child.is_dir() else 0o600)


def prepare(case_dir, case):
    work = WORK_ROOT / case_dir.name
    if work.exists():
        make_writable(work)
        shutil.rmtree(work)
    root = work / "root"
    root.mkdir(parents=True)
    files = case_dir / "files"
    if files.is_dir():
        shutil.copytree(files, root, dirs_exist_ok=True)
    shutil.copy(MIME_TYPES, work / "mime.types")
    config = case["config"].replace("{{port}}", str(PORT)).replace("{{root}}", str(root))
    config = config.replace("{{dir}}", str(work)).replace("{{backend}}", f"127.0.0.1:{BACKEND_PORT}")
    indented = "\n".join("    " + line if line else line for line in config.strip().splitlines())
    (work / "nginx.conf").write_text(WRAPPER.format(dir=work, config=indented))
    for path in [work, *work.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))
    # Deepest first, so a directory that loses access is changed after what is in it.
    for name, mode in sorted(case.get("modes", {}).items(), key=lambda m: -m[0].count("/")):
        path = (root / name).resolve()
        if root.resolve() not in path.parents:
            raise ValueError(f"modes: {name} is not under files/")
        path.chmod(int(mode, 8))
    return work


def run_nginx(work, requests):
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    started = subprocess.run(
        ["docker", "run", "-d", "--name", CONTAINER_NAME, "--network", "host",
         "-v", f"{work}:{work}:ro", NGINX_IMAGE, "nginx", "-c", f"{work}/nginx.conf",
         "-g", "daemon off;"],
        capture_output=True, text=True,
    )
    if started.returncode != 0:
        raise RuntimeError(f"docker run failed: {started.stderr.strip()}")

    def alive():
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
                               capture_output=True, text=True)
        return state.stdout.strip() == "true"

    try:
        if not wait_for_port(PORT, STARTUP_TIMEOUT, alive):
            logs = subprocess.run(["docker", "logs", CONTAINER_NAME], capture_output=True, text=True)
            return None, (logs.stdout + logs.stderr).strip()[-2000:]
        return [send_raw(raw) for raw in requests], None
    finally:
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)


def run_twinx(binary, work, requests, sandbox=None):
    if not binary.is_file():
        return None, f"twinx binary not found at {binary}"
    if sandbox is not None:
        return run_twinx_sandboxed(binary, work, requests, sandbox)
    log = open(work / "twinx.log", "wb")
    process = subprocess.Popen([str(binary), "-c", str(work / "nginx.conf")],
                               cwd=work, stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_for_port(PORT, STARTUP_TIMEOUT, lambda: process.poll() is None):
            log.flush()
            return None, (work / "twinx.log").read_text(errors="replace")[-2000:]
        return [send_raw(raw) for raw in requests], None
    finally:
        process.kill()
        process.wait()
        log.close()


def run_twinx_sandboxed(binary, work, requests, profiles):
    """Run twinx in a container that can write nothing but its own /tmp (and the
    coverage profiles, when the judge measures them)."""
    subprocess.run(["docker", "rm", "-f", SANDBOX_NAME], capture_output=True)
    command = [
        "docker", "run", "-d", "--name", SANDBOX_NAME, "--network", "host",
        "--user", SANDBOX_USER, "--read-only", "--tmpfs", "/tmp:rw,exec,size=64m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "1g",
        "-v", f"{binary}:/usr/local/bin/twinx:ro", "-v", f"{work}:{work}:ro", "-w", str(work),
    ]
    if profiles:
        # twinx is pid 1 in every container, so the profile is named after the case instead.
        command += ["-v", f"{profiles}:/profiles", "-e", f"LLVM_PROFILE_FILE=/profiles/twinx-{work.name}-%c.profraw"]
    command += [SANDBOX_IMAGE, "twinx", "-c", str(work / "nginx.conf")]
    started = subprocess.run(command, capture_output=True, text=True)
    if started.returncode != 0:
        raise RuntimeError(f"docker run failed: {started.stderr.strip()}")

    def alive():
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", SANDBOX_NAME],
                               capture_output=True, text=True)
        return state.stdout.strip() == "true"

    try:
        if not wait_for_port(PORT, STARTUP_TIMEOUT, alive):
            logs = subprocess.run(["docker", "logs", SANDBOX_NAME], capture_output=True, text=True)
            return None, (logs.stdout + logs.stderr).strip()[-2000:]
        return [send_raw(raw) for raw in requests], None
    finally:
        subprocess.run(["docker", "rm", "-f", SANDBOX_NAME], capture_output=True)


def run_case(case_dir, binary, sandbox=None):
    case = tomllib.loads((case_dir / "case.toml").read_text())
    requests = [r["raw"].encode("latin-1") for r in case.get("requests", [])]
    work = prepare(case_dir, case)
    nginx, nginx_error = run_nginx(work, requests)
    # nginx's workers read the files as another user, so a case that sets modes runs
    # twinx as another user too: in the sandbox, whether or not --sandbox was given.
    if case.get("modes") and sandbox is None:
        sandbox = ""
    twinx, twinx_error = run_twinx(binary, work, requests, sandbox)
    result = {"case": str(case_dir.relative_to(REPO)), "description": case.get("description", "")}
    if nginx is None:
        # A configuration nginx refuses must be refused by twinx too.
        result["nginx_startup_error"] = nginx_error
        result["passed"] = twinx is None
        if twinx is not None:
            result["problems"] = ["nginx refused to start with this configuration, twinx started"]
        return result
    if twinx is None:
        result["passed"] = False
        result["problems"] = [f"twinx did not start: {twinx_error}"]
        result["requests"] = [
            {"request": raw.decode("latin-1"), "passed": False, "nginx": parse(expected)}
            for raw, expected in zip(requests, nginx)
        ]
        return result
    outcomes = []
    for raw, expected, actual in zip(requests, nginx, twinx):
        expected, actual = parse(expected), parse(actual)
        problems = diff(expected, actual)
        outcomes.append({"request": raw.decode("latin-1"), "passed": not problems, "problems": problems,
                         "nginx": expected, "twinx": actual})
    result["requests"] = outcomes
    result["passed"] = all(o["passed"] for o in outcomes)
    return result


def find_cases(paths):
    cases = []
    for path in paths:
        path = (REPO / path).resolve() if not Path(path).is_absolute() else Path(path)
        if (path / "case.toml").is_file():
            cases.append(path)
        else:
            cases.extend(sorted(p.parent for p in path.rglob("case.toml")))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", default=["cases"], help="case directories or parents of them")
    parser.add_argument("--twinx", default=str(REPO / "target" / "release" / "twinx"))
    parser.add_argument("--out", help="write the full results as JSON to this file")
    parser.add_argument("--sandbox", action="store_true",
                        help=f"run twinx in a container ({SANDBOX_IMAGE}) that can write only its own /tmp")
    parser.add_argument("--profiles", help="with --sandbox, a directory twinx writes coverage profiles to")
    args = parser.parse_args()

    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("harness: cannot reach the Docker daemon", file=sys.stderr)
        return 2
    cases = find_cases(args.paths)
    if not cases:
        print("harness: no cases found", file=sys.stderr)
        return 2

    backend = Backend(("127.0.0.1", BACKEND_PORT), EchoHandler)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    started = time.monotonic()
    results = []
    try:
        for case_dir in cases:
            sandbox = (str(Path(args.profiles).resolve()) if args.profiles else "") if args.sandbox else None
            result = run_case(case_dir, Path(args.twinx).resolve(), sandbox)
            results.append(result)
            print(("PASS " if result["passed"] else "FAIL ") + result["case"])
            for problem in result.get("problems", []):
                print("     " + problem)
            for outcome in result.get("requests", []):
                if not outcome["passed"] and "problems" in outcome:
                    print("     request: " + outcome["request"].split("\r\n")[0])
                    for problem in outcome["problems"]:
                        print("       " + problem)
    finally:
        backend.shutdown()

    passed = sum(r["passed"] for r in results)
    summary = {
        "nginx_version": NGINX_VERSION,
        "nginx_image": NGINX_IMAGE,
        "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 1),
        "cases": len(results),
        "cases_passed": passed,
    }
    print(f"\n{passed}/{len(results)} cases passed in {summary['seconds']}s")
    if args.out:
        Path(args.out).write_text(json.dumps({"summary": summary, "results": results}, indent=2))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
