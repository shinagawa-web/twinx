"""An upstream that switches protocols and sends back what it gets, and the load for it.

    python3 /perf/websocket.py serve <port>
    python3 /perf/websocket.py load <port> <path> <connections> <seconds>

The load prints one JSON line. Neither frames its bytes: a proxy passes them as they are.
"""

import asyncio
import json
import sys
import time

MESSAGE = b"x" * 125


async def echo(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError):
        pass
    writer.close()


async def serve(port):
    server = await asyncio.start_server(echo, "127.0.0.1", port, backlog=4096)
    await server.serve_forever()


async def connect(port, path):
    """A connection that switched protocols, or None and the status."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".encode())
    head = await reader.readuntil(b"\r\n\r\n")
    return reader, writer, int(head.split()[1])


async def probe(port, path):
    reader, writer, status = await connect(port, path)
    echoed = 0
    if status == 101:
        writer.write(MESSAGE)
        echoed = len(await asyncio.wait_for(reader.readexactly(len(MESSAGE)), 5))
    writer.close()
    return {"status": status, "echoed": echoed}


async def load(port, path, connections, seconds):
    messages, latencies, errors = 0, [], 0
    end = time.monotonic() + seconds

    async def one():
        nonlocal messages, errors
        try:
            reader, writer, status = await connect(port, path)
            if status != 101:
                errors += 1
                return
            while (now := time.monotonic()) < end:
                writer.write(MESSAGE)
                await reader.readexactly(len(MESSAGE))
                latencies.append(time.monotonic() - now)
                messages += 1
            writer.close()
        except (OSError, asyncio.IncompleteReadError):
            errors += 1

    started = time.monotonic()
    await asyncio.gather(*(one() for _ in range(connections)))
    took = time.monotonic() - started
    latencies.sort()
    at = lambda q: round(latencies[int(len(latencies) * q)] * 1000, 3) if latencies else 0
    print(json.dumps({"requests": messages, "rps": round(messages / took, 1), "p50_ms": at(.5), "p90_ms": at(.9),
                      "p99_ms": at(.99), "max_ms": at(.99999), "socket_errors": errors, "bad_status": 0}))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        asyncio.run(serve(int(sys.argv[2])))
    else:
        asyncio.run(load(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), float(sys.argv[5])))
