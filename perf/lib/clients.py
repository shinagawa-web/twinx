"""Clients that hold connections: reading slowly, sending slowly, or idle."""

import json
import socket
import ssl
import struct
import sys
import time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def context(h2):
    c = ssl.create_default_context()
    c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
    if h2:
        c.set_alpn_protocols(["h2"])
    return c


def frame(kind, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", stream) + payload


def h2_get(path):
    """The preface, SETTINGS, and a GET of path on stream 1."""
    p, host = path.encode(), b"localhost"
    block = b"\x82\x87" + b"\x04" + bytes([len(p)]) + p + b"\x01" + bytes([len(host)]) + host
    return PREFACE + frame(4, 0, 0) + frame(1, 5, 1, block)


def connect(port, spec, small):
    s = socket.socket()
    if small:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    s.settimeout(5)
    s.connect(("127.0.0.1", port))
    if spec.get("tls"):
        s = context(spec.get("h2")).wrap_socket(s, server_hostname="localhost")
        if spec.get("h2") and s.selected_alpn_protocol() != "h2":
            raise OSError("no h2")
    return s


def answered(data, h2):
    """Whether what came first is a good answer: HTTP/1.1 200, or :status 200 in HEADERS (0x88)."""
    if not h2:
        return data.startswith(b"HTTP/1.1 200")
    at = 0
    while len(data) >= at + 9:
        n, kind = int.from_bytes(data[at:at + 3], "big"), data[at + 3]
        if kind == 1:
            return len(data) > at + 9 and data[at + 9] == 0x88
        at += 9 + n
    return False


def receive(s):
    """What is there to read, "" for nothing yet, None once closed."""
    try:
        return s.recv(65536) or None
    except (BlockingIOError, ssl.SSLWantReadError, TimeoutError):
        return b""
    except OSError:
        return None


def readers(port, spec, seconds):
    """Ask for path, and read 64 KB every 0.3 s; over HTTP/2, the window is opened by as much."""
    socks, h2 = [], spec.get("h2")
    for _ in range(spec["count"]):
        s = connect(port, spec, True)
        s.sendall(h2_get(spec["path"]) if h2 else f"GET {spec['path']} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        s.setblocking(False)
        socks.append(s)
    end, first, ok, closed, total = time.monotonic() + seconds, {}, set(), set(), 0
    while time.monotonic() < end:
        for i, s in enumerate(socks):
            if i in closed:
                continue
            data = receive(s)
            if data is None:
                closed.add(i)
                continue
            total += len(data)
            if i not in ok and len(first.get(i, b"")) < 4096:
                first[i] = first.get(i, b"") + data
                if answered(first[i], h2):
                    ok.add(i)
            if h2 and data:
                try:
                    s.sendall(frame(8, 0, 0, struct.pack(">I", 65536)) + frame(8, 0, 1, struct.pack(">I", 65536)))
                except OSError:
                    closed.add(i)
        time.sleep(0.3)
    return {"clients": len(socks), "clients_ok": len(ok - closed), "read_mb": round(total / 1e6, 1)}


def uploaders(port, spec, seconds):
    """POST 10 MB, 128 KB every 0.1 s; they do not finish within the time."""
    size, socks = 10 << 20, []
    for _ in range(spec["count"]):
        s = connect(port, spec, False)
        s.sendall(f"POST {spec['path']} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {size}\r\n\r\n".encode())
        s.setblocking(False)
        socks.append(s)
    end, closed, sent = time.monotonic() + seconds, set(), 0
    piece = b"u" * (128 << 10)
    while time.monotonic() < end:
        for i, s in enumerate(socks):
            if i in closed:
                continue
            if receive(s) != b"":
                # Closed, or answered before the body was sent.
                closed.add(i)
                continue
            try:
                sent += s.send(piece)
            except (BlockingIOError, ssl.SSLWantWriteError):
                pass
            except OSError:
                closed.add(i)
        time.sleep(0.1)
    return {"clients": len(socks), "clients_ok": len(socks) - len(closed), "sent_mb": round(sent / 1e6, 1)}


def idle(port, spec, seconds):
    """Connections that made one request each, then held open."""
    socks, ok, h2 = [], 0, spec.get("h2")
    for _ in range(spec["count"]):
        try:
            s = connect(port, spec, False)
            s.sendall(h2_get(spec["path"]) if h2 else f"GET {spec['path']} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            data = b""
            for _ in range(20):
                got = receive(s)
                if not got:
                    break
                data += got
                if answered(data, h2):
                    ok += 1
                    break
            socks.append(s)
        except OSError:
            pass
    time.sleep(seconds)
    return {"clients": spec["count"], "clients_ok": ok}


if __name__ == "__main__":
    spec = json.loads(sys.argv[2])
    print(json.dumps({"readers": readers, "uploaders": uploaders, "idle": idle}[spec["client"]](
        int(sys.argv[1]), spec, float(sys.argv[3]))))
