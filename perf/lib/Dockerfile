# nginx 1.30.6, pinned by the digest twinx's harness uses, with wrk, h2load and openssl to load it and Python to run the measurements.
FROM nginx@sha256:42c68eab6f7e22611786a9fe1d1c019e275c50185bd54b8f75dc2b9184322703
RUN apt-get update && apt-get install -y --no-install-recommends python3 wrk nghttp2-client openssl curl iproute2 && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1
COPY bench.py scenarios.py certs.py clients.py slow_upstream.py dns.py websocket.py report.lua post.lua chunked.lua /perf/
