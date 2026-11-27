"""An upstream that answers every request after a fixed delay, with keep-alive.

    python3 /perf/slow_upstream.py <port> <delay seconds>

Answers 100 bytes, closing the connection only when the request asks for it
(Connection: close, or HTTP/1.0 without keep-alive). GET /_status answers at
once with the connections accepted so far, in nginx's stub_status format, so
the bench reads it the same way as the other upstream's. GET /first answers
with the beginning at once, and the rest 200 ms later.
"""

import asyncio
import sys

PORT, DELAY = int(sys.argv[1]), float(sys.argv[2])
BODY = b"s" * 100
accepted = 0


def wants_close(head):
    lines = head.lower().split(b"\r\n")
    connection = next((l.split(b":", 1)[1].strip() for l in lines[1:] if l.startswith(b"connection:")), b"")
    if lines[0].endswith(b"http/1.0"):
        return connection != b"keep-alive"
    return connection == b"close"


class Upstream(asyncio.Protocol):
    def connection_made(self, transport):
        global accepted
        accepted += 1
        self.transport, self.buffer = transport, b""

    def data_received(self, data):
        self.buffer += data
        while b"\r\n\r\n" in self.buffer:
            head, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
            close = wants_close(head)
            if head.startswith(b"GET /_status "):
                status = f"Active connections: 0 \nserver accepts handled requests\n {accepted} {accepted} 0 \n"
                self.answer(status.encode(), True)
            elif head.startswith(b"GET /first "):
                self.transport.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(BODY), BODY[:50]))
                asyncio.get_running_loop().call_later(0.2, self.rest, close)
            else:
                asyncio.get_running_loop().call_later(DELAY, self.answer, BODY, close)

    def rest(self, close):
        if not self.transport.is_closing():
            self.transport.write(BODY[50:])
            if close:
                self.transport.close()

    def answer(self, body, close):
        if self.transport.is_closing():
            return
        self.transport.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s\r\n%s"
                             % (len(body), b"Connection: close\r\n" if close else b"", body))
        if close:
            self.transport.close()


async def main():
    server = await asyncio.get_running_loop().create_server(Upstream, "127.0.0.1", PORT, backlog=4096)
    await server.serve_forever()


asyncio.run(main())
