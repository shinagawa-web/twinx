"""Measures nginx and twinx under the same load, in one container.

    python3 /perf/bench.py --twinx /twinx/twinx --tag v0.4.0 --out /results/v0.4.0.json [--group tls] [--scenario <name>]... [--quick]
        [--kept-nginx /kept/nginx.json]

The servers run the same configuration, pinned to the machine's first CPU;
wrk, the slow clients and the upstreams run on the others.
Each scenario in scenarios.py is there for one feature. Its servers are started for it alone,
again for each round, with only the configuration it needs, and each one's answer is checked before any
load: nginx's against what the scenario expects, twinx's against nginx's. It is
then measured on every server in turn, a few rounds in a different order each round,
and the median is kept: absolute numbers move with the machine, servers measured in
the same run much less.
With --kept-nginx, nginx is measured only in the scenarios that file does not have:
in the others twinx is checked against the answer kept, and measured alone.
Every measurement records latency percentiles, errors, CPU time and its kernel
share, memory, threads, socket queues and TCP counters.
"""

import argparse
import asyncio
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import threading
import time

import certs
import websocket
from scenarios import (ANY, BACKEND, BACKEND_H2, BACKEND_TLS, BACKEND_VERIFIED, DNS, ECHO, MTIME, POST_SIZE, SCENARIOS, SLOW,
                       SLOW_UPSTREAM, SLOW_UPSTREAM_DELAY, TEXT)

WORK = "/work"
PORTS = {"nginx": 8080, "twinx": 8082}
TICK = os.sysconf("SC_CLK_TCK")

# Both servers get enough connections per worker for 1000 clients plus their
# upstream connections.
MAIN = """worker_processes {workers};
events {{ worker_connections 8192; }}
"""
# nginx runs without root here, so the temporary paths it creates at start-up go
# under its prefix; twinx does not have the modules behind them.
NGINX_HTTP = """    fastcgi_temp_path {prefix}/fastcgi_temp;
    uwsgi_temp_path {prefix}/uwsgi_temp;
    scgi_temp_path {prefix}/scgi_temp;
"""

CONF = """daemon off;
pid {prefix}/logs/nginx.pid;
error_log {prefix}/logs/error.log warn;
{main}
http {{
    access_log off;
    client_body_temp_path {prefix}/client_body_temp;
    proxy_temp_path {prefix}/proxy_temp;
{only}
    {before}
    server {{
        listen 127.0.0.1:{port} {listen};
        server_name localhost;
        {server}
    }}
    {http}
}}
"""

BACKEND_CONF = """daemon off;
pid {prefix}/logs/nginx.pid;
error_log {prefix}/logs/error.log warn;
worker_processes 1;
events {{ worker_connections 8192; }}
http {{
    access_log off;
    client_body_temp_path {prefix}/client_body_temp;
    proxy_temp_path {prefix}/proxy_temp;
    client_body_buffer_size 128k;
    client_max_body_size 0;
{only}
    server {{
        listen 127.0.0.1:{port};
        root {prefix}/html;
        location / {{ return 200 "{body}"; }}
        location ~ \\.bin$ {{ }}
        location = /headers {{ {headers} return 200 "{body}"; }}
        # Reads all of a body before it answers.
        location = /upload {{ proxy_pass http://127.0.0.1:{port}/; }}
        # SSI, with nothing to do in it, leaves the answer without a length.
        location = /chunked.html {{ default_type text/html; ssi on; }}
        location = /rewritten {{ add_header Location http://inner/x; add_header X-Hidden x;
            add_header Set-Cookie "a=1; Domain=inner.test; Path=/in/x"; return 200 "{body}"; }}
        location = /failing {{ return 503; }}
        location = /vary {{ add_header Vary Accept-Language; return 200 "{body}"; }}
        location = /_status {{ stub_status; }}
    }}
    # Connections here stay, so that what is measured is their use, not their making.
    server {{
        listen 127.0.0.1:{tls} ssl;
        listen 127.0.0.1:{h2};
        http2 on;
        keepalive_requests 1000000000;
        ssl_certificate {work}/c.pem;
        ssl_certificate_key {work}/k.pem;
        location / {{ return 200 "{body}"; }}
    }}
    server {{
        listen 127.0.0.1:{verified} ssl;
        ssl_certificate {work}/c.pem;
        ssl_certificate_key {work}/k.pem;
        ssl_client_certificate {work}/c.pem;
        ssl_verify_client on;
        location / {{ add_header X-Verified $ssl_client_verify; return 200 "{body}"; }}
    }}
}}
"""


def cpus():
    """One CPU for the servers, the others this process may use for the load.

    twinx serves from one worker, so a second CPU would go to nginx alone."""
    mine = sorted(os.sched_getaffinity(0))
    return mine[:1], mine[1:] or mine


def cpu_list(cs):
    return ",".join(str(c) for c in cs)


def write_prefix(prefix, files=(), gzipped=False):
    """An empty directory for a server, with files: a size or text for each path."""
    shutil.rmtree(prefix, ignore_errors=True)
    os.makedirs(f"{prefix}/logs")
    os.makedirs(f"{prefix}/conf")
    for path, content in dict(files).items():
        data = content.encode() if isinstance(content, str) else b"m" * content
        os.makedirs(os.path.dirname(f"{prefix}/{path}"), exist_ok=True)
        for name, body in [(path, data)] + ([(path + ".gz", gzip.compress(data))] if gzipped else []):
            with open(f"{prefix}/{name}", "wb") as f:
                f.write(body)
            os.utime(f"{prefix}/{name}", (MTIME, MTIME))


def write_conf(name, q, prefix, workers):
    """The configuration of scenario q for server name."""
    nginx, port = name == "nginx", PORTS[name]
    put = lambda text: text.replace("@prefix@", prefix).replace("@port@", str(port))
    return CONF.format(
        prefix=prefix, port=port, listen=q.get("listen", ""),
        main=MAIN.format(workers=workers),
        only=NGINX_HTTP.format(prefix=prefix) if nginx else "",
        before=put(q.get("before", "")), http=put(q.get("http", "")), server=put(q["server"]))


def definition(q):
    """What scenario q is, short: nginx's kept measurements of it hold while this stays the same."""
    return hashlib.sha256(json.dumps({k: v for k, v in q.items() if k != "feature"}, sort_keys=True).encode()).hexdigest()[:16]


def answer(port, q):
    """What the server answers to the scenario's request, of what expect has; raises
    RuntimeError when it does not."""
    if q.get("tool") == "websocket":
        try:
            return asyncio.run(websocket.probe(port, q["path"]))
        except (OSError, EOFError, TimeoutError, ValueError, IndexError) as e:
            raise RuntimeError(f"{type(e).__name__}: {e}")
    head = f"{WORK}/head"
    cmd = ["curl", "-sSk", "--max-time", "10", "--http2" if q.get("tool") == "h2load" else "--http1.1",
           "-D", head, "-o", "/dev/null", "-w", "%{http_code} %{size_download} %{http_version}"]
    for h in q.get("headers", []) + (["Connection: close"] if q.get("close") else []):
        cmd += ["-H", h]
    if q.get("chunked"):
        cmd += ["-H", "Transfer-Encoding: chunked"]
    if q.get("post") or q.get("chunked"):
        cmd += ["--data-binary", f"@{WORK}/body", "-H", "Expect:"]
    if q.get("cert"):
        cmd += ["--cert", cert_of(q)[0], "--key", cert_of(q)[1]]
    out = subprocess.run(cmd + [url(port, q)], capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f"curl: {out.stderr.strip()}")
    status, length, version = out.stdout.split()
    got = {"status": int(status), "length": int(length), "version": version}
    for line in open(head, newline="").read().split("\r\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            got[k.strip().lower()] = v.strip()
    for k, v in q.get("nginx_too", {}).items():
        if port == PORTS["nginx"] and got.get(k) != v:
            raise RuntimeError(f"{k} is {got.get(k)}, not {v}")
    return {k: got.get(k) for k in q["expect"]}


def url(port, q):
    return f"{'https' if 'ssl' in q.get('listen', '') else 'http'}://{q.get('host', '127.0.0.1')}:{port}{q['path']}"


def cert_of(q):
    """The client's certificate and key of a scenario."""
    return (f"{WORK}/c.pem", f"{WORK}/k.pem") if q["cert"] == "c" else (f"{WORK}/{q['cert']}.pem", f"{WORK}/{q['cert']}.key")


def start(binary, prefix, conf, cpu, name):
    open(f"{prefix}/conf/nginx.conf", "w").write(conf)
    stderr = f"{prefix}/logs/stderr"
    proc = subprocess.Popen(
        ["taskset", "-c", cpu_list(cpu), binary, "-p", prefix + "/", "-c", "conf/nginx.conf", "-e", "logs/error.log"],
        stdout=subprocess.DEVNULL, stderr=open(stderr, "wb"))
    return Server(name, binary, prefix, conf, cpu, proc, stderr)


class Server:
    def __init__(self, name, binary, prefix, conf, cpu, proc, stderr):
        self.name, self.binary, self.prefix, self.conf, self.cpu = name, binary, prefix, conf, cpu
        self.proc, self.stderr, self.seen = proc, stderr, 0
        self.port = PORTS.get(name, BACKEND)
        self.workers = set()

    def wait(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} did not start: {self.error_text()}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError(f"{self.name} is not listening")
        # The master listens before it starts its workers. A twinx tag from before
        # it had any is left with none to note.
        deadline = time.time() + 1
        while not self.note_workers() and time.time() < deadline:
            time.sleep(0.05)

    def error_text(self):
        text = ""
        for path in (self.stderr, f"{self.prefix}/logs/error.log"):
            try:
                text += open(path, errors="replace").read()
            except OSError:
                pass
        return text.strip()[-800:]

    def alive(self):
        """The process runs, and so does every worker noted. A worker that died may be
        left as a zombie, or replaced under another PID, so the same PIDs are asked for."""
        return self.proc.poll() is None and self.workers <= set(self.children())

    def note_workers(self):
        """Adds the workers running now to those that must go on running."""
        self.workers |= set(self.children())
        return self.workers

    def children(self):
        """The running children of the process, its workers: zombies are left out."""
        # taskset execs the server, so proc.pid is the server itself.
        root = self.proc.pid
        found = []
        for p in os.listdir("/proc"):
            if p.isdigit():
                try:
                    state, parent = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()[:2]
                except OSError:
                    continue
                if int(parent) == root and state not in "ZX":
                    found.append(int(p))
        return found

    def pids(self):
        """The process and its workers."""
        return [self.proc.pid] + self.children()

    def usage(self):
        """Resident memory in KiB, threads, and user and system CPU ticks, summed over its processes."""
        rss = threads = user = system = 0
        for pid in self.pids():
            try:
                for line in open(f"/proc/{pid}/status"):
                    if line.startswith("VmRSS:"):
                        rss += int(line.split()[1])
                    elif line.startswith("Threads:"):
                        threads += int(line.split()[1])
                fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
                user, system = user + int(fields[11]), system + int(fields[12])
                if pid == self.proc.pid:
                    # And what its workers that ended took, as a reload ends them.
                    user, system = user + int(fields[13]), system + int(fields[14])
            except (OSError, IndexError, ValueError):
                pass
        return rss, threads, (user, system)

    def new_panics(self):
        try:
            lines = open(self.stderr, errors="replace").read().splitlines()
        except OSError:
            return []
        panics = [l.split("panicked at", 1)[1].strip() for l in lines if "panicked at" in l]
        new, self.seen = panics[self.seen:], len(panics)
        return new

    def stop(self):
        # Workers outlive a master that was killed, and keep its port.
        workers = self.children() if self.proc.poll() is None else self.workers
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for pid in workers:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def sockets(port):
    """The server side of its TCP sockets: the LISTEN socket's accept queue (connections
    waiting for accept), and over its established connections, the bytes received but
    not read yet (Recv-Q), the connections with any, and the bytes sent but not
    acknowledged yet (Send-Q)."""
    accept = recv = waiting = send = 0
    want = f":{port:04X}"
    try:
        lines = open("/proc/net/tcp").read().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        f = line.split()
        if not f[1].endswith(want):
            continue
        tx, rx = (int(x, 16) for x in f[4].split(":"))
        if f[3] == "0A":
            accept += rx
        elif f[3] == "01":
            recv, send, waiting = recv + rx, send + tx, waiting + (rx > 0)
    return accept, recv, waiting, send


def tcp_counters():
    """Counters of this network namespace: listen queue overflows and drops, and retransmitted segments."""
    out = {}
    for path, prefix in (("/proc/net/netstat", "TcpExt:"), ("/proc/net/snmp", "Tcp:")):
        try:
            rows = [l.split() for l in open(path) if l.startswith(prefix)]
        except OSError:
            continue
        for names, values in zip(rows[::2], rows[1::2]):
            out.update(zip(names[1:], (int(v) for v in values[1:])))
    return {"listen_overflows": out.get("ListenOverflows"), "listen_drops": out.get("ListenDrops"),
            "retransmitted_segments": out.get("RetransSegs")}


def listen_backlog(port):
    """The LISTEN socket's backlog, as ss shows it in Send-Q."""
    out = subprocess.run(["ss", "-ltnH", f"sport = :{port}"], capture_output=True, text=True).stdout.split()
    return int(out[2]) if len(out) > 2 else None


class Sampler:
    """Peak memory, threads and socket queues of a server while something runs,
    and the CPU time and TCP counters it took."""

    def __init__(self, server):
        self.server, self.stop_event = server, threading.Event()
        self.peak = {"rss": 0, "threads": 0, "accept": 0, "recv": 0, "waiting": 0, "send": 0}
        self.rss = []

    def __enter__(self):
        _, _, self.ticks0 = self.server.usage()
        self.counters0, self.started = tcp_counters(), time.monotonic()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def _run(self):
        while not self.stop_event.is_set():
            rss, threads, _ = self.server.usage()
            now = {"rss": rss, "threads": threads}
            self.rss.append(rss)
            queues = sockets(self.server.port)
            if queues:
                now.update(zip(("accept", "recv", "waiting", "send"), queues))
            self.peak = {k: max(v, now.get(k, 0)) for k, v in self.peak.items()}
            self.stop_event.wait(0.2)

    def __exit__(self, *exc):
        self.stop_event.set()
        self.thread.join()
        _, _, ticks1 = self.server.usage()
        seconds = time.monotonic() - self.started
        user, system = (max(0, b - a) / TICK for a, b in zip(self.ticks0, ticks1))
        self.cpu = {"cpu_seconds": round(user + system, 2), "user_seconds": round(user, 2),
                    "system_seconds": round(system, 2),
                    # Of one CPU: the servers are pinned to len(server_cpus) CPUs.
                    "cpu_percent": round((user + system) / seconds * 100, 1)}
        counters1 = tcp_counters()
        self.counters = {k: counters1[k] - self.counters0[k] for k in counters1
                         if counters1[k] is not None and self.counters0[k] is not None}


def upstream_accepts(port):
    """Connections an upstream has accepted so far (stub_status)."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.sendall(b"GET /_status HTTP/1.0\r\nHost: localhost\r\n\r\n")
        data = b""
        while chunk := s.recv(4096):
            data += chunk
        s.close()
        return int(data.split(b"\r\n\r\n", 1)[1].splitlines()[2].split()[0])
    except (OSError, IndexError, ValueError):
        return None


def wrk(port, q, seconds, load_cpu):
    """Requests with keep-alive, or, with close, each asking for Connection: close, so wrk
    opens a connection for each."""
    threads = max(1, min(len(load_cpu), q["connections"]))
    cmd = ["taskset", "-c", cpu_list(load_cpu), "wrk", "-t", str(threads), "-c", str(q["connections"]),
           "-d", f"{seconds}s", "--timeout", "5s", "-s", "/perf/chunked.lua" if q.get("chunked") else "/perf/post.lua" if q.get("post") else "/perf/report.lua"]
    for h in q.get("headers", []) + (["Connection: close"] if q.get("close") else []):
        cmd += ["-H", h]
    cmd.append(url(port, q))
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 60).stdout
    except subprocess.TimeoutExpired:
        return {"error": "wrk did not finish"}
    lines = [l for l in out.splitlines() if l.startswith("{")]
    if not lines:
        return {"error": "wrk printed no result: " + out.strip()[-300:]}
    r = json.loads(lines[-1])
    seconds_run = r["duration_us"] / 1e6
    errors = r["connect_errors"] + r["read_errors"] + r["write_errors"] + r["timeouts"]
    return {
        "requests": r["requests"],
        "rps": round((r["requests"] - r["bad_status"]) / seconds_run, 1),
        "mb_per_s": round(r["bytes"] / seconds_run / 1e6, 2),
        "p50_ms": r["p50_us"] / 1000, "p90_ms": r["p90_us"] / 1000, "p99_ms": r["p99_us"] / 1000,
        "max_ms": r["max_us"] / 1000,
        "socket_errors": errors, "bad_status": r["bad_status"],
    }


def h2load(port, q, seconds, load_cpu):
    threads = max(1, min(len(load_cpu), q["connections"]))
    cmd = ["taskset", "-c", cpu_list(load_cpu), "h2load", "-t", str(threads), "-c", str(q["connections"]),
           "-m", str(q["streams"]), "-D", str(seconds)]
    if q.get("post"):
        cmd += ["-d", f"{WORK}/body"]
    for h in q.get("headers", []):
        cmd += ["-H", h]
    if q.get("literal"):
        # Nothing is kept in the table, so every request has its headers in full.
        cmd += ["--encoder-header-table-size=0"]
    try:
        out = subprocess.run(cmd + [url(port, q)], capture_output=True, text=True, timeout=seconds + 60).stdout
    except subprocess.TimeoutExpired:
        return {"error": "h2load did not finish"}
    finished = re.search(r"finished in [\d.]+\w+, ([\d.]+) req/s, ([\d.]+)([KMG]?)B/s", out)
    counts = re.search(r"requests: .*?(\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, (\d+) timeout", out)
    codes = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", out)
    slowest = re.search(r"time for request:\s+\S+\s+([\d.]+)(us|ms|s)", out)
    if not (finished and counts and codes):
        return {"error": "h2load printed no result: " + out.strip()[-300:]}
    done, _, failed, errored, timeouts = (int(x) for x in counts.groups())
    bad = sum(int(x) for x in codes.groups()[1:])
    r = {"requests": done, "rps": float(finished[1]),
         "mb_per_s": round(float(finished[2]) * {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[finished[3]] / 1e6, 2),
         # failed counts bad statuses as well as errors.
         "socket_errors": max(0, failed - bad) if failed >= errored else errored, "bad_status": bad}
    if slowest:
        r["max_ms"] = round(float(slowest[1]) * {"us": 1e-3, "ms": 1, "s": 1e3}[slowest[2]], 3)
    return r


def s_time(port, q, seconds, load_cpu):
    """openssl s_time on each load CPU: bad_status counts the connections that were not
    resumed when they were to be, or were when they were not."""
    cmd = ["openssl", "s_time", "-connect", f"127.0.0.1:{port}", "-www", q["path"], "-time", str(seconds),
           "-reuse" if q.get("resumed") else "-new"]
    if q.get("cert"):
        cmd += ["-cert", cert_of(q)[0], "-key", cert_of(q)[1]]
    procs = [subprocess.Popen(["taskset", "-c", str(c)] + cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
             for c in load_cpu]
    requests = bad = 0
    rps = 0.0
    for proc in procs:
        try:
            out = proc.communicate(timeout=seconds + 60)[0]
        except subprocess.TimeoutExpired:
            for other in procs:
                other.kill()
            return {"error": "s_time did not finish"}
        took = re.search(r"(\d+) connections in (\d+) real seconds", out)
        # One character for each connection: r when it was resumed.
        marks = max((l for l in out.splitlines() if re.fullmatch(r"[rt*]+", l)), key=len, default="")
        if not took or not marks:
            return {"error": "s_time printed no result: " + out.strip()[-300:]}
        n, resumed = int(took[1]), marks.count("r")
        # With -reuse, the first connection makes the session and is not counted.
        requests += n
        rps += n / max(1, int(took[2]))
        bad += max(0, n - resumed) if q.get("resumed") else resumed
    return {"requests": requests, "rps": round(rps, 1), "socket_errors": 0, "bad_status": bad}


def websocket_load(port, q, seconds, load_cpu):
    cmd = ["taskset", "-c", cpu_list(load_cpu), "python3", "/perf/websocket.py", "load", str(port), q["path"],
           str(q["connections"]), str(seconds)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 60)
        return json.loads(out.stdout)
    except (subprocess.TimeoutExpired, ValueError):
        return {"error": "the WebSocket load printed no result"}


TOOLS = {"wrk": wrk, "h2load": h2load, "s_time": s_time, "websocket": websocket_load}


def load(port, q, seconds, load_cpu):
    return TOOLS[q.get("tool", "wrk")](port, q, seconds, load_cpu)


def reloading(server, q, seconds, load_cpu):
    """The load while the server reloads every 0.7 s."""
    before, stop_event, sent = server.note_workers(), threading.Event(), []
    before = set(before)

    def hup():
        while not stop_event.wait(0.7):
            had = set(server.children())
            try:
                os.kill(server.proc.pid, signal.SIGHUP)
            except ProcessLookupError:
                return
            # Until there is a worker that was not there before.
            began = time.monotonic()
            while time.monotonic() < began + 2 and not set(server.children()) - had:
                time.sleep(0.005)
            sent.append((time.monotonic() - began) * 1000)

    thread = threading.Thread(target=hup)
    thread.start()
    r = load(server.port, q, seconds, load_cpu)
    stop_event.set()
    thread.join()
    time.sleep(1)
    now = set(server.children())
    r["reloads"] = len(sent)
    if sent:
        r["reload_ms"] = round(statistics.median(sent), 1)
    if sent and now and not now & before:
        # The new workers are the ones that must go on running.
        server.workers = now
    elif sent and server.proc.poll() is None:
        r["error"] = f"the workers before {len(sent)} reloads are still there: {sorted(now & before)} of {sorted(now)}"
        server.workers = now
    return r


def held(port, q, seconds, load_cpu):
    """What perf/lib/clients.py does with connections held open."""
    spec = {k: q[k] for k in ("client", "count", "path", "tls", "h2") if k in q}
    cmd = ["taskset", "-c", cpu_list(load_cpu), "python3", "/perf/clients.py", str(port), json.dumps(spec), str(seconds)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 90)
        return json.loads(out.stdout)
    except (subprocess.TimeoutExpired, ValueError):
        return {"error": "the clients printed no result"}


def first_bytes(port, q, load_cpu, n=40):
    """The time to the first byte, each on a connection of its own."""
    cmd = ["taskset", "-c", cpu_list(load_cpu), "curl", "-sSk", "--max-time", "10", "-o", "/dev/null",
           "--http2" if q.get("tool") == "h2load" else "--http1.1", "-w", "%{http_code} %{time_starttransfer}", url(port, q)]
    times = []
    for _ in range(n):
        out = subprocess.run(cmd, capture_output=True, text=True).stdout.split()
        if len(out) == 2 and int(out[0]) == q["expect"]["status"]:
            times.append(float(out[1]) * 1000)
    if not times:
        return {"error": "no request was answered as it should be"}
    times.sort()
    return {"requests": n, "bad_status": n - len(times), "socket_errors": 0, "p50_ms": round(statistics.median(times), 3),
            "p99_ms": round(times[int(len(times) * .99)], 3), "max_ms": round(times[-1], 3)}


def beside(port, q, seconds, load_cpu):
    """The load, while another is on the server."""
    other = {"connections": 64, "listen": q.get("listen", ""), **q["beside"]}
    result = []
    thread = threading.Thread(target=lambda: result.append(load(port, other, seconds + 1, load_cpu)))
    thread.start()
    time.sleep(0.5)
    r = load(port, q, seconds, load_cpu)
    thread.join()
    if "error" in result[0] or not result[0]["requests"]:
        return {"error": f"the load beside it: {result[0].get('error', 'no requests')}"}
    r["beside_requests"] = result[0]["requests"]
    return r


class SlowClients:
    """Connections that send a little every second and never finish their request."""

    HEAD = {"headers": b"GET /return HTTP/1.1\r\nHost: localhost\r\n"}
    DRIP = {"headers": b"X-Slow: 1\r\n"}

    def __init__(self, port, kind, n):
        self.kind, self.socks, self.failed = kind, [], 0
        self.stop_event = threading.Event()
        for _ in range(n):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=3)
                s.sendall(self.HEAD[kind])
                s.setblocking(False)
                self.socks.append(s)
            except OSError:
                self.failed += 1
        self.closed = set()
        self.thread = threading.Thread(target=self._drip, daemon=True)
        self.thread.start()

    def _drip(self):
        while not self.stop_event.wait(1):
            for i, s in enumerate(self.socks):
                if i in self.closed:
                    continue
                try:
                    s.send(self.DRIP[self.kind])
                except OSError:
                    self.closed.add(i)

    def still_open(self):
        """Connections the server has neither closed nor answered."""
        n = 0
        for i, s in enumerate(self.socks):
            if i in self.closed:
                continue
            try:
                if s.recv(1, socket.MSG_PEEK) is not None:
                    continue  # answered or closed (b"")
            except BlockingIOError:
                n += 1
            except OSError:
                pass
        return n

    def close(self):
        self.stop_event.set()
        self.thread.join()
        for s in self.socks:
            s.close()


def median_of(runs):
    """The median of each number over the rounds, and any error text."""
    ok = [r for r in runs if "error" not in r]
    out = {}
    if ok:
        for key in ok[0]:
            values = [r[key] for r in ok if isinstance(r.get(key), (int, float))]
            if values:
                out[key] = round(statistics.median(values), 3)
    errors = [r["error"] for r in runs if "error" in r]
    if errors:
        out["errors"] = errors
    # How far the rounds were apart, as a share of the median.
    cpu = [r["cpu_ms_per_1k_requests"] for r in ok if r.get("cpu_ms_per_1k_requests") is not None]
    if len(cpu) > 1 and out.get("cpu_ms_per_1k_requests"):
        out["cpu_spread"] = round((max(cpu) - min(cpu)) / out["cpu_ms_per_1k_requests"], 3)
    # Whichever round it was in.
    out.pop("died", None)
    if any(r.get("died") for r in runs):
        out["died"] = True
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--twinx", required=True)
    parser.add_argument("--nginx", default="/usr/sbin/nginx")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--twinx-label", help="what --twinx is, for the summary (default: the tag)")
    parser.add_argument("--group", help="only the scenarios of this group")
    parser.add_argument("--only", help="only the scenarios whose name this regular expression is found in")
    parser.add_argument("--scenario", action="append", help="only the scenario of this exact name; can be given more than once")
    parser.add_argument("--quick", action="store_true", help="one short round, to try things out")
    parser.add_argument("--kept-nginx", help="nginx's measurements kept from a tag (perf/lib/keep.py): nginx is "
                        "measured only in the scenarios not there")
    args = parser.parse_args()
    unknown = sorted(set(args.scenario or []) - {q["name"] for q in SCENARIOS})
    if unknown:
        raise SystemExit("no such scenario: " + "; ".join(unknown))

    binaries = {"nginx": args.nginx, "twinx": args.twinx}
    names = list(binaries)
    kept_nginx = json.load(open(args.kept_nginx))["scenarios"] if args.kept_nginx else {}

    def kept_of(q):
        """nginx's kept measurements of q, unless nginx was not measured in it or q has changed since."""
        k = kept_nginx.get(q["name"])
        if not k or "not_measured" in k["nginx"] or k.get("definition", definition(q)) != definition(q):
            return None
        return k

    rounds, seconds, warmup = (1, 2, 1) if args.quick else (5, 3, 1)
    server_cpu, load_cpu = cpus()
    os.sched_setaffinity(0, load_cpu)

    wanted = [q for q in SCENARIOS if args.group in (None, q["group"])
              and (not args.only or re.search(args.only, q["name"]))
              and (not args.scenario or q["name"] in args.scenario)]
    if not wanted:
        raise SystemExit("no such scenario")
    certs.make(WORK)
    with open(f"{WORK}/body", "wb") as f:
        f.write(b"p" * POST_SIZE)
    backend_prefix = f"{WORK}/backend"
    write_prefix(backend_prefix, {"html/4k.bin": 4096, "html/1m.bin": 1 << 20, "html/10m.bin": 10 << 20,
                                   "html/chunked.html": TEXT})
    backend = start(args.nginx, backend_prefix, BACKEND_CONF.format(
        prefix=backend_prefix, port=BACKEND, tls=BACKEND_TLS, h2=BACKEND_H2, verified=BACKEND_VERIFIED, work=WORK, body="b" * 100,
        headers=" ".join(f"add_header X-H{i} fifteen;" for i in range(1, 16)),
        only=NGINX_HTTP.format(prefix=backend_prefix)), load_cpu, "backend")
    backend.wait()
    slow_upstream = subprocess.Popen(
        ["taskset", "-c", cpu_list(load_cpu), "python3", "/perf/slow_upstream.py",
         str(SLOW_UPSTREAM), str(SLOW_UPSTREAM_DELAY)])
    echo = subprocess.Popen(
        ["taskset", "-c", cpu_list(load_cpu), "python3", "/perf/websocket.py", "serve", str(ECHO)])
    dns = subprocess.Popen(["taskset", "-c", cpu_list(load_cpu), "python3", "/perf/dns.py", str(DNS)])
    deadline = time.time() + 10
    while upstream_accepts(SLOW_UPSTREAM) is None:
        if time.time() > deadline or slow_upstream.poll() is not None:
            raise RuntimeError("the slow upstream did not start")
        time.sleep(0.05)

    servers, restarts, panics = {}, {n: 0 for n in names}, {n: [] for n in names}

    def stop(name):
        s = servers.pop(name)
        panics[name] += s.new_panics()
        s.stop()

    def log_of(name, q):
        return f"{WORK}/{name}/{q['log']}".replace("@port@", str(PORTS[name]))

    def logged(path):
        """Whether something was written to path, and empties it."""
        deadline = time.time() + 2
        while time.time() < deadline:
            if os.path.exists(path) and os.path.getsize(path):
                os.truncate(path, 0)
                return True
            time.sleep(0.05)
        return False

    def prepare(q, names, kept):
        """Starts the servers for a round of a scenario and checks their answers. Returns, for each,
        its idle state and listen backlog, or why it is not measured."""
        state, reference = {}, kept and kept["nginx"].get("answer")
        for name in names:
            prefix = f"{WORK}/{name}"
            write_prefix(prefix, q.get("files", ()), q.get("gzipped", False))
            servers[name] = start(binaries[name], prefix, write_conf(name, q, prefix, len(server_cpu)), server_cpu, name)
            try:
                servers[name].wait()
                state[name] = {}
            except RuntimeError as e:
                state[name] = {"not_measured": str(e)}
                stop(name)
        time.sleep(0.5)
        for name in list(servers):
            rss, threads, _ = servers[name].usage()
            state[name].update(idle_rss_mb=round(rss / 1024, 1), idle_threads=threads,
                               listen_backlog=listen_backlog(PORTS[name]))
        for name in list(servers):
            if q.get("primed"):
                # What is cached from it is what the check and the load find.
                try:
                    answer(PORTS[name], q)
                except RuntimeError:
                    pass
            try:
                got = answer(PORTS[name], q)
            except RuntimeError as e:
                got = str(e)
            if name == "nginx":
                reference = got
                want = dict(q["expect"])
                if isinstance(got, dict):
                    want.update({k: got[k] for k, v in want.items() if v == ANY})
                state[name]["answer"] = got
            elif kept and reference is None:
                # Kept from before nginx's answers were: what the scenario expects, and
                # whatever twinx gives where nginx's could be anything.
                want = {k: got.get(k) if v == ANY and isinstance(got, dict) else v for k, v in q["expect"].items()}
            else:
                want = reference
            if got == want and q.get("log") and not logged(log_of(name, q)):
                got, want = "without writing its access log", "with it"
            if got != want:
                state[name] = {"not_measured": f"answered {got}, not {want}"}
                stop(name)
        if "nginx" not in servers and not kept:
            # Nothing to compare with: the scenario itself is wrong.
            for name in list(servers):
                state[name] = {"not_measured": "nginx is not measured"}
                stop(name)
        return state

    def check(name):
        """Records panics and restarts a server that died, or lost a worker."""
        s = servers[name]
        panics[name] += s.new_panics()
        if not s.alive():
            restarts[name] += 1
            s.stop()
            servers[name] = start(s.binary, s.prefix, s.conf, s.cpu, name)
            servers[name].wait()
            return False
        return True

    def measured(name, fn, upstream=None, per_request=True):
        s = servers[name]
        s.note_workers()
        accepts0 = upstream_accepts(upstream) if upstream else None
        with Sampler(s) as sample:
            r = fn(s)
        accepts1 = upstream_accepts(upstream) if upstream else None
        if per_request and r.get("requests") and accepts0 is not None and accepts1 is not None:
            # One of the accepts is the second stub_status request itself.
            r["upstream_connections_per_request"] = round((accepts1 - accepts0 - 1) / r["requests"], 4)
        p = sample.peak
        r.update(peak_rss_mb=round(p["rss"] / 1024, 1), peak_threads=p["threads"],
                 peak_accept_queue=p["accept"], peak_recv_q_kb=round(p["recv"] / 1024, 1),
                 peak_connections_unread=p["waiting"], peak_send_q_kb=round(p["send"] / 1024, 1),
                 **sample.cpu, **sample.counters)
        if r.get("requests") and "error" not in r and per_request:
            r["cpu_ms_per_1k_requests"] = round(sample.cpu["cpu_seconds"] * 1e6 / r["requests"], 3)
        if len(sample.rss) > 8:
            # From a quarter of the way to the end.
            r["rss_growth_mb"] = round((sample.rss[-1] - sample.rss[len(sample.rss) // 4]) / 1024, 1)
        if not check(name):
            r["died"] = True
        return r

    scenarios = []
    for q in wanted:
        sc = {k: v for k, v in q.items() if k != "files"}
        sc["definition"] = definition(q)
        kept = kept_of(q)
        here_names = ["twinx"] if kept else names
        if q.get("direct"):
            # The same load straight to the upstream, as what the proxy adds to.
            straight = {**q, "path": "/"}
            load(q["direct"], straight, warmup, load_cpu)
            sc["direct_load"] = load(q["direct"], straight, seconds, load_cpu)
        runs, state, measuring = {n: [] for n in here_names}, {}, here_names
        scenario_rounds = 1 if args.quick else q.get("rounds", rounds)
        wanted_seconds = seconds if args.quick else q.get("seconds", seconds)
        for r in range(scenario_rounds):
            # Started again for each round: what a process is like (where its memory lies,
            # say) holds for all of its rounds, and is not what the scenario is about.
            now = prepare(q, measuring, kept)
            if not state:
                state = now
                measuring = [n for n in here_names if n in servers]
            for name in measuring:
                if name not in servers:
                    runs[name].append({"error": now[name]["not_measured"]})
            here = [n for n in measuring if n in servers]
            for name in here if q["kind"] in ("load", "slow", "beside") else ():
                load(PORTS[name], q, warmup, load_cpu)
            # A different order each round, so no server is always measured first.
            first = r % len(here) if here else 0
            for name in here[first:] + here[:first]:
                port = PORTS[name]

                def run(s):
                    if q.get("reload"):
                        return reloading(s, q, wanted_seconds, load_cpu)
                    if q["kind"] == "load":
                        return load(port, q, wanted_seconds, load_cpu)
                    if q["kind"] == "memory":
                        return held(port, q, 1 if q["client"] == "idle" else wanted_seconds, load_cpu)
                    if q["kind"] == "first":
                        return first_bytes(port, q, load_cpu, 5 if args.quick else 40)
                    if q["kind"] == "beside":
                        return beside(port, q, wanted_seconds, load_cpu)
                    clients = SlowClients(port, "headers", SLOW)
                    time.sleep(1.5)
                    res = load(port, q, wanted_seconds, load_cpu)
                    res["slow_connected"] = len(clients.socks)
                    res["slow_kept_open"] = clients.still_open()
                    clients.close()
                    return res

                runs[name].append(measured(name, run, q.get("accepts"), q["kind"] == "load"))
                if q.get("log"):
                    os.truncate(log_of(name, q), 0)
                if q["kind"] != "load":
                    time.sleep(1)
            for name in here:
                check(name)
                stop(name)
            if not measuring:
                break
        sc["rounds"] = scenario_rounds
        sc["servers"] = {n: {**state[n], "median": median_of(runs[n]), "runs": runs[n]} for n in here_names}
        scenarios.append(sc)
        print(q["name"] + ": " + ", ".join(
            f"{n} " + (f"not measured ({state[n]['not_measured']})" if "not_measured" in state[n]
                       else f"{sc['servers'][n]['median'].get('rps')} rps") for n in here_names)
              + (", nginx kept" if kept else ""), flush=True)

    backend.stop()
    slow_upstream.terminate()
    echo.terminate()
    dns.terminate()

    nginx_version = subprocess.run([args.nginx, "-v"], capture_output=True, text=True).stderr.strip()
    cpuinfo = open("/proc/cpuinfo").read()
    model = next((l.split(":", 1)[1].strip() for l in cpuinfo.splitlines()
                  if re.match(r"(model name|Model)\s*:", l)), "")
    if not model:
        # On aarch64, which does not name it.
        model = " ".join(f"{k} {v}" for k, v in re.findall(r"CPU (implementer|part)\s*: (\S+)", cpuinfo)[:2])
    result = {
        "tag": args.tag,
        "group": args.group,
        "only": args.only,
        "names": args.scenario,
        "servers": names,
        "labels": {"nginx": "nginx", "twinx": args.twinx_label or args.tag},
        "date": time.strftime("%Y-%m-%d", time.gmtime()),
        "machine": {"arch": platform.machine(), "cpu": model, "server_cpus": server_cpu, "load_cpus": load_cpu},
        "nginx": nginx_version,
        "rounds": rounds, "seconds": seconds,
        "restarts": restarts,
        "panics": panics,
        "scenarios": scenarios,
    }
    with open(args.out, "w") as f:
        json.dump(result, f, indent=1)


if __name__ == "__main__":
    main()
