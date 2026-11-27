"""A DNS server that answers every A question with 127.0.0.1, for 60 s, and others with nothing.

    python3 /perf/dns.py <port>
"""

import socket
import struct
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    query, client = s.recvfrom(4096)
    end = query.index(b"\0", 12) + 5
    kind = struct.unpack(">H", query[end - 4:end - 2])[0]
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1]) if kind == 1 else b""
    s.sendto(query[:2] + b"\x81\x80" + struct.pack(">HHHH", 1, bool(answer), 0, 0) + query[12:end] + answer, client)
