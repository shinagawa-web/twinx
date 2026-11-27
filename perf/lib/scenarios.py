"""What is measured: a scenario for each feature, level with nginx or not, so that a
regression in it shows. See docs/performance.md.

Each scenario has:

group     which job it runs in; servers compared are always compared within one.
feature   what of twinx it is there for.
kind      "load": requests are made as fast as they are answered, with tool:
            "wrk" (the default) against path, connections at once, with keep-alive or
              Connection: close on every request (close), headers, and post (64 KB) or
              chunked (1 MB POSTs, in chunks).
            "h2load" with streams at once on each connection, headers, and post; literal
              has every header sent in full.
            "s_time", openssl's, a process on each load CPU that makes connections one
              after another, and a request on each: resumed or not, with a client's cert
              (its name in /work) or not.
            "websocket" (perf/lib/websocket.py): connections that send 125 bytes and wait
              for them to come back.
            reload: the server is told to reload every 0.7 s meanwhile.
            seconds and rounds, when not the usual.
          "slow": the load of the first scenario beside SLOW connections that send a
            header line a second.
          "beside": a load whose latency is measured beside another (beside) on the server.
          "first": the time to the first byte of one request on a connection of its own.
          "memory": a client of perf/lib/clients.py (readers, uploaders or idle), count of it.
before, http, server, listen
          what its configuration has in those places (before: ahead of the servers); @prefix@ is the server's directory.
files     what is in that directory: a size, or text; gzipped has a .gz of it beside.
log       the access log the configuration writes.
expect    the answer nginx must give for the scenario to measure what it is named for:
          the status, the body's length, the HTTP version, and headers by name. ANY is
          whatever nginx gives. The other servers must give what nginx gave.
nginx_too  what nginx must give besides, and the others need not.
primed    the request is made once before the check, so that the check and the load find
          what it left in the cache.
direct    the port of an upstream loaded directly too, so the latency the proxy adds
          can be read.
accepts   the port to ask how many connections the upstreams accepted.
host      in the URL and SNI, when not 127.0.0.1.
"""

ANY = "any"
SLOW = 1000
BACKEND, BACKEND_TLS, BACKEND_H2, SLOW_UPSTREAM, ECHO = 8090, 8490, 8190, 8091, 8092
BACKEND_VERIFIED, DNS = 8491, 8053
SLOW_UPSTREAM_DELAY = 0.1
POST_SIZE = 64 << 10
# When every file served was last modified, for If-Modified-Since.
MTIME, MTIME_HTTP = 1767225600, "Thu, 01 Jan 2026 00:00:00 GMT"

RETURN = 'location = /return { return 200 "ok\\n"; }'
OK = {"status": 200, "length": 3, "connection": "keep-alive"}
STATIC = "root @prefix@/html; location /static/ { }"
CERT = "ssl_certificate /work/c.pem; ssl_certificate_key /work/k.pem; "
# h2load does not reconnect after the GOAWAY that keepalive_requests brings.
H2 = CERT + "http2 on; keepalive_requests 1000000000; "
OK2 = {"status": 200, "length": 3, "version": "2"}
EC = "ssl_certificate /work/ec.pem; ssl_certificate_key /work/ec.key; "
# What a browser sends.
HEADERS = [f"{k}: {v}" for k, v in (
    ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9,ja;q=0.8"), ("Cache-Control", "max-age=0"), ("DNT", "1"),
    ("Priority", "u=0, i"), ("Referer", "https://www.example.com/a/page/before/this/one?with=arguments"),
    ("Sec-CH-UA", '"Chromium";v="140", "Not=A?Brand";v="24"'), ("Sec-CH-UA-Mobile", "?0"),
    ("Sec-CH-UA-Platform", '"Linux"'), ("Sec-Fetch-Dest", "document"), ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-User", "?1"), ("Upgrade-Insecure-Requests", "1"),
    ("X-Request-ID", "2f1c9a6e-5b0d-4f6f-9a55-0c8b7e3d1f42"), ("X-Forwarded-For", "203.0.113.7"),
    ("Cookie", "session=" + "0123456789abcdef" * 64))]
TEXT = " ".join(f"word{i * 7919 % 5000} <li>item {i}</li>" for i in range(3000))[:64 << 10]


def proxied(length):
    return {"status": 200, "length": length, "connection": "keep-alive"}


def cached(more="", upstream=BACKEND, valid="1h", ahead=""):
    """Proxying to upstream through a cache, which tells whether a request was a HIT."""
    return {"before": "proxy_cache_path @prefix@/cache levels=1:2 keys_zone=C:10m;",
            "http": f"upstream backend {{ server 127.0.0.1:{upstream}; }}",
            "server": f"{ahead}location / {{ proxy_pass http://backend; proxy_cache C; proxy_cache_valid 200 {valid}; "
                      f"add_header X-Cache-Status $upstream_cache_status;{' ' + more if more else ''} }}"}


def group(name, *scenarios):
    return [{"group": name, "kind": "load", "connections": 64, **s} for s in scenarios]


SCENARIOS = [
    *group("http",
        # How heavy one request is.
        {"feature": "connections", "name": "return, 64 connections", "path": "/return",
         "server": RETURN, "expect": OK},
        # What many connections do: the I/O model, and the listen backlog.
        {"feature": "connections", "name": "return, 1000 connections", "rounds": 9, "path": "/return", "connections": 1000,
         "server": RETURN, "expect": OK},
        # How heavy a new connection is.
        {"feature": "connections", "name": "return, a new connection per request, 64 connections", "path": "/return",
         "close": True, "server": RETURN, "expect": {**OK, "connection": "close"}},
        # Whether slow clients hold up the others: the first scenario's load beside them.
        {"feature": "connections", "name": f"return, 64 connections, beside {SLOW} slow clients", "kind": "slow",
         "path": "/return", "server": RETURN, "expect": OK},
        # Choosing among regular expressions, rewriting, and reading variables.
        {"feature": "configuration", "name": "regex location, rewrite and variables", "path": "/re/12/abc",
         "server": r"location ~ ^/re/(\d+)/([a-z]+)$ { set $a $1; rewrite ^/re/(\d+)/(.*)$ /rw?x=$1 last; } "
                   r'location = /rw { add_header X-A "$host-$a-$arg_x"; return 200 "$uri $args $remote_addr\n"; }',
         "expect": {"status": 200, "length": ANY, "x-a": "127.0.0.1-12-12"}},
        {"feature": "configuration", "name": "one of 200 locations", "path": "/loc150/x",
         "server": " ".join(f'location /loc{i}/ {{ return 200 "ok {i}\\n"; }}' for i in range(200)),
         "expect": {"status": 200, "length": len("ok 150\n")}},
        {"feature": "configuration", "name": "one of 200 server names", "path": "/", "headers": ["Host: s150.test"],
         "server": 'return 200 "ok\\n";',
         "http": " ".join(f'server {{ listen 127.0.0.1:@port@; server_name s{i}.test; return 200 "ok {i}\\n"; }}'
                          for i in range(200)),
         "expect": {"status": 200, "length": len("ok 150\n")}},
        {"feature": "logging", "name": "return, access_log on", "path": "/return",
         "server": "access_log @prefix@/logs/access.log; " + RETURN, "log": "logs/access.log", "expect": OK},
    ),
    *group("config",
        {"feature": "configuration", "name": "one of 50 regex locations", "path": "/r49/x",
         "server": " ".join(f'location ~ ^/r{i}/ {{ return 200 "ok {i}\\n"; }}' for i in range(50)),
         "expect": {"status": 200, "length": len("ok 49\n")}},
        {"feature": "configuration", "name": "one of 50 wildcard and 50 regex server names", "path": "/",
         "headers": ["Host: a49.r.test"], "server": 'return 200 "ok\\n";',
         "http": " ".join(f'server {{ listen 127.0.0.1:@port@; server_name *.w{i}.test; return 200 "w {i}\\n"; }} '
                          f'server {{ listen 127.0.0.1:@port@; server_name ~^a{i}\\.r\\.test$; return 200 "r {i}\\n"; }}'
                          for i in range(50)),
         "expect": {"status": 200, "length": len("r 49\n")}},
        {"feature": "configuration", "name": "error_page, to an internal redirect", "path": "/none",
         "server": "location = /none { error_page 404 =200 /out; return 404; } "
                   'location = /out { return 200 "ok\\n"; }', "expect": OK},
        {"feature": "headers", "name": "return, 18 headers and a 1 KB cookie", "path": "/return", "headers": HEADERS,
         "server": RETURN, "expect": OK},
        # A path for each request, so that the file is opened by name.
        {"feature": "logging", "name": "return, access_log to a path with a variable", "path": "/return",
         "server": "root @prefix@/html; access_log @prefix@/logs/access-$server_port.log; " + RETURN,
         # nginx opens such a path only when the root exists.
         "files": {"html/x": 1},
         "log": "logs/access-@port@.log", "expect": OK},
        {"feature": "logging", "name": "return, access_log with a log_format of 12 variables", "path": "/return",
         "before": "log_format long '$remote_addr $remote_user [$time_local] \"$request\" $status $body_bytes_sent "
                 "\"$http_referer\" \"$http_user_agent\" $request_time $upstream_addr $request_length $server_port';",
         "server": "access_log @prefix@/logs/access.log long; " + RETURN, "log": "logs/access.log", "expect": OK},
        {"feature": "static files", "name": "index, alias, if and expires", "path": "/a/d/",
         "server": "location /a/ { alias @prefix@/html/; index none.html i.html; expires 1h; "
                   'if ($request_method = POST) { return 405; } }',
         "files": {"html/d/i.html": 4096}, "expect": {**proxied(4096), "cache-control": "max-age=3600"}},
        {"feature": "static files", "name": "static 1m with sendfile", "path": "/static/1m.bin",
         "server": "sendfile on; " + STATIC, "files": {"html/static/1m.bin": 1 << 20}, "expect": proxied(1 << 20)},
        {"feature": "headers", "name": "return, add_header of the server and the location, add_header_inherit merge",
         "path": "/return", "server": "add_header X-S s; location = /return { add_header_inherit merge; "
                                      'add_header X-L l; return 200 "ok\\n"; }',
         "expect": {**OK, "x-s": "s", "x-l": "l"}},
    ),
    *group("files",
        # Whether a large file costs memory.
        {"feature": "static files", "name": "static 1m, 64 connections", "path": "/static/1m.bin",
         "server": STATIC, "files": {"html/static/1m.bin": 1 << 20}, "expect": proxied(1 << 20)},
        {"feature": "static files", "name": "static 4k", "rounds": 9, "path": "/static/4k.bin",
         "server": STATIC, "files": {"html/static/4k.bin": 4096}, "expect": proxied(4096)},
        {"feature": "static files", "name": "try_files, to a 4k file", "rounds": 9, "path": "/none/x",
         "server": "root @prefix@/html; location /none/ { try_files $uri /static/4k.bin =404; }",
         "files": {"html/static/4k.bin": 4096}, "expect": proxied(4096)},
        {"feature": "static files", "name": "range, 4k of 1m", "path": "/static/1m.bin",
         "headers": ["Range: bytes=1000-5095"], "server": STATIC, "files": {"html/static/1m.bin": 1 << 20},
         "expect": {"status": 206, "length": 4096, "content-range": "bytes 1000-5095/1048576"}},
        {"feature": "static files", "name": "304", "rounds": 9, "path": "/static/4k.bin",
         "headers": [f"If-Modified-Since: {MTIME_HTTP}"], "server": STATIC, "files": {"html/static/4k.bin": 4096},
         "expect": {"status": 304, "length": 0, "last-modified": MTIME_HTTP}},
        {"feature": "compression", "name": "gzip, 64k of text", "path": "/static/64k.txt",
         "headers": ["Accept-Encoding: gzip"],
         "server": "default_type text/plain; gzip on; gzip_types text/plain; " + STATIC,
         "files": {"html/static/64k.txt": TEXT}, "expect": {"status": 200, "content-encoding": "gzip"}},
        {"feature": "compression", "name": "gunzip, 64k of text", "path": "/static/64k.txt",
         "server": "gzip_static always; gunzip on; " + STATIC, "files": {"html/static/64k.txt": TEXT}, "gzipped": True,
         "expect": {"status": 200, "length": len(TEXT), "content-encoding": None}},
        {"feature": "compression", "name": "gzip_static, 64k of text", "rounds": 9, "path": "/static/64k.txt",
         "headers": ["Accept-Encoding: gzip"], "server": "gzip_static on; " + STATIC,
         "files": {"html/static/64k.txt": TEXT}, "gzipped": True,
         "expect": {"status": 200, "length": ANY, "content-encoding": "gzip"}},
    ),
    *group("proxy",
        # Whether the proxy reuses upstream connections, and the latency it adds.
        {"feature": "proxying", "name": "proxy, 64 connections", "rounds": 9, "path": "/proxy",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location /proxy { proxy_pass http://backend; }",
         "direct": BACKEND, "accepts": BACKEND, "expect": proxied(100)},
        # How many requests waiting on a slow upstream it can hold.
        {"feature": "proxying", "connections": 1000, "path": "/slowproxy",
         "name": f"proxy to an upstream answering after {SLOW_UPSTREAM_DELAY * 1000:.0f} ms, 1000 connections",
         "http": f"upstream slow {{ server 127.0.0.1:{SLOW_UPSTREAM}; }}",
         "server": "location /slowproxy { proxy_pass http://slow; }",
         "direct": SLOW_UPSTREAM, "accepts": SLOW_UPSTREAM, "expect": proxied(100)},
        {"feature": "proxying", "name": "proxy, 1m answer", "path": "/1m.bin",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; }", "accepts": BACKEND, "expect": proxied(1 << 20)},
        {"feature": "proxying", "name": "proxy, 64k POST", "path": "/post", "post": True,
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; }", "accepts": BACKEND, "expect": proxied(100)},
        # Half of the requests are tried on a server that refuses connections first.
        {"feature": "proxying", "name": "proxy, next_upstream", "path": "/proxy",
         "http": f"upstream flaky {{ server 127.0.0.1:1 max_fails=0; server 127.0.0.1:{BACKEND} max_fails=0; }}",
         "server": "location / { proxy_pass http://flaky; }", "accepts": BACKEND, "expect": proxied(100)},
        {"feature": "proxying", "name": "WebSocket, 125 bytes there and back", "tool": "websocket", "path": "/ws",
         "server": f"location /ws {{ proxy_pass http://127.0.0.1:{ECHO}; proxy_http_version 1.1; "
                   'proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; }',
         "expect": {"status": 101, "echoed": 125}},
        # Headers set and passed on, as a proxy in use does.
        {"feature": "proxying", "name": "proxy, 18 request headers, 4 set, 15 in the answer", "path": "/headers",
         "headers": HEADERS,
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; proxy_set_header Host $host; "
                   "proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; "
                   "proxy_set_header X-Forwarded-Proto $scheme; }",
         "accepts": BACKEND, "expect": {**proxied(100), "x-h15": "fifteen"}},
        # An upstream made for each request.
        {"feature": "proxying", "name": "proxy to an address in a variable", "path": "/proxy",
         "server": f"location / {{ set $u 127.0.0.1:{BACKEND}; proxy_pass http://$u; }}",
         "accepts": BACKEND, "expect": proxied(100)},
        {"feature": "proxying", "name": "proxy, cookies, redirects and headers rewritten", "path": "/rewritten",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; proxy_hide_header X-Hidden; "
                   "proxy_redirect http://inner/ http://outer/; proxy_cookie_domain inner.test outer.test; "
                   "proxy_cookie_path /in/ /out/; proxy_cookie_flags a secure httponly; }",
         "accepts": BACKEND, "expect": {**proxied(100), "x-hidden": None, "location": "http://outer/x",
                                        "set-cookie": ANY}},
        {"feature": "proxying", "name": "proxy, errors answered by error_page", "path": "/failing",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; proxy_intercept_errors on; error_page 503 =200 /out; } "
                   'location = /out { return 200 "ok\\n"; }', "accepts": BACKEND, "expect": OK},
        {"feature": "proxying", "name": "proxy, 1m answer, proxy_buffering off", "path": "/1m.bin",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; proxy_buffering off; }",
         "accepts": BACKEND, "expect": proxied(1 << 20)},
        {"feature": "resolver", "name": "proxy to a name looked up", "path": "/proxy",
         "server": f"resolver 127.0.0.1:{DNS} ipv6=off; "
                   f"location / {{ set $u backend.test; proxy_pass http://$u:{BACKEND}; }}",
         "accepts": BACKEND, "expect": proxied(100)},
        {"feature": "proxying", "name": "proxy, not kept alive", "path": "/proxy",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; keepalive 0; }}",
         "server": "location / { proxy_pass http://backend; }", "accepts": BACKEND, "expect": proxied(100)},
        # What a check made before the request does: the request without its body and headers.
        {"feature": "proxying", "name": "proxy, 64k POST, its body and headers not passed on", "path": "/post",
         "post": True, "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; proxy_method GET; proxy_pass_request_body off; "
                   'proxy_pass_request_headers off; proxy_set_header Content-Length ""; }',
         "accepts": BACKEND, "expect": proxied(100)},
    ),
    *group("upstreams",
        # Fewer connections kept than clients: the pool is taken from and given back to all the time.
        {"feature": "upstream keepalive", "name": "proxy, a keepalive pool of 16, 1000 connections", "path": "/proxy",
         "connections": 1000,
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; keepalive 16; }}",
         "server": 'location / { proxy_pass http://backend; proxy_http_version 1.1; proxy_set_header Connection ""; }',
         "accepts": BACKEND, "expect": proxied(100)},
        {"feature": "TLS upstreams", "name": "proxy to TLS, kept alive", "path": "/proxy",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND_TLS}; }}",
         "server": "location / { proxy_pass https://backend; }", "accepts": BACKEND,
         "expect": proxied(100)},
        {"feature": "TLS upstreams", "name": "proxy to TLS, not kept alive", "path": "/proxy",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND_TLS}; keepalive 0; }}",
         "server": "location / { proxy_pass https://backend; }", "accepts": BACKEND,
         "expect": proxied(100)},
        {"feature": "HTTP/2 upstreams", "name": "proxy to HTTP/2, 64 connections", "path": "/proxy",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND_H2}; }}",
         "server": "location / { proxy_pass http://backend; proxy_http_version 2; }",
         "accepts": BACKEND, "expect": proxied(100)},
        {"feature": "TLS upstreams", "name": "proxy to TLS, verified, with a client certificate", "path": "/proxy",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND_VERIFIED}; keepalive 0; }}",
         "server": "location / { proxy_pass https://backend; proxy_ssl_verify on; proxy_ssl_name localhost; "
                   "proxy_ssl_trusted_certificate /work/c.pem; proxy_ssl_certificate /work/c.pem; "
                   "proxy_ssl_certificate_key /work/k.pem; proxy_ssl_session_reuse off; }",
         "accepts": BACKEND, "expect": {**proxied(100), "x-verified": "SUCCESS"}},
        {"feature": "HTTP/2 upstreams", "name": "proxy to HTTP/2 over TLS, 64 connections", "path": "/proxy",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND_TLS}; }}",
         "server": "location / { proxy_pass https://backend; proxy_http_version 2; }",
         "accepts": BACKEND, "expect": proxied(100)},
        {"feature": "HTTP/2 upstreams", "name": "proxy to HTTP/2, 64k POST", "path": "/post", "post": True,
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND_H2}; }}",
         "server": "location / { proxy_pass http://backend; proxy_http_version 2; }",
         "accepts": BACKEND, "expect": proxied(100)},
        {"feature": "proxying", "name": "proxy, 64k chunked answer with a trailer", "path": "/chunked.html",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; add_trailer X-T t; }",
         "accepts": BACKEND, "expect": {"status": 200, "length": ANY}, "nginx_too": {"transfer-encoding": "chunked"}},
        # What an application behind a proxy usually sends: no length, and text to compress.
        {"feature": "proxying", "name": "proxy, 64k chunked answer", "path": "/chunked.html",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "location / { proxy_pass http://backend; }",
         "accepts": BACKEND, "expect": {"status": 200, "length": ANY}, "nginx_too": {"transfer-encoding": "chunked"}},
        {"feature": "compression", "name": "proxy, 64k chunked answer, gzip", "path": "/chunked.html",
         "headers": ["Accept-Encoding: gzip"],
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "gzip on; location / { proxy_pass http://backend; }",
         "accepts": BACKEND, "expect": {"status": 200, "content-encoding": "gzip"}},
        {"feature": "proxying", "name": "proxy, 1m chunked POST", "path": "/post", "chunked": True,
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": "client_max_body_size 0; location / { proxy_pass http://backend; }",
         "accepts": BACKEND, "expect": proxied(100)},
        # The usual place of a proxy: TLS before, plain HTTP behind.
        {"feature": "TLS", "name": "TLS, proxied to plain HTTP", "path": "/proxy", "listen": "ssl",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": CERT + "location / { proxy_pass http://backend; }",
         "accepts": BACKEND, "expect": proxied(100)},
    ),
    *group("cache",
        # How heavy an answer from the cache is.
        {"feature": "proxy cache", "name": "proxy_cache, HIT", "path": "/proxy", "primed": True, **cached(),
         "expect": {**proxied(100), "x-cache-status": "HIT"}},
        {"feature": "proxy cache", "name": "proxy_cache, HIT of 1m", "path": "/1m.bin", "primed": True, **cached(),
         "expect": {**proxied(1 << 20), "x-cache-status": "HIT"}},
        # A key for each request: every answer is fetched and written to the cache.
        {"feature": "proxy cache", "name": "proxy_cache, MISS stored, a key per request", "path": "/proxy",
         **cached("proxy_cache_key $request_id;"),
         "accepts": BACKEND, "expect": {**proxied(100), "x-cache-status": "MISS"}},
        {"feature": "proxy cache", "name": "proxy_cache, HIT, a key of 5 variables", "path": "/proxy",
         "headers": ["Cookie: session=0123456789abcdef", "Accept-Language: en-US,en;q=0.9"], "primed": True,
         **cached("proxy_cache_key $scheme$proxy_host$request_uri$cookie_session$http_accept_language;"),
         "expect": {**proxied(100), "x-cache-status": "HIT"}},
        {"feature": "proxy cache", "name": "proxy_cache, 304 from a HIT", "path": "/4k.bin", "primed": True,
         "headers": [f"If-Modified-Since: {MTIME_HTTP}"], **cached(),
         "expect": {"status": 304, "length": 0, "x-cache-status": "HIT"}},
        {"feature": "proxy cache", "name": "proxy_cache, range, 4k of a HIT of 1m", "path": "/1m.bin", "primed": True,
         "headers": ["Range: bytes=1000-5095"], **cached(),
         "expect": {"status": 206, "length": 4096, "content-range": "bytes 1000-5095/1048576", "x-cache-status": "HIT"}},
        {"feature": "proxy cache", "name": "proxy_cache, HIT of an answer with Vary", "path": "/vary", "primed": True,
         "headers": ["Accept-Language: ja"], **cached(),
         "expect": {**proxied(100), "x-cache-status": "HIT", "vary": "Accept-Language"}},
        {"feature": "proxy cache", "name": "proxy_cache, bypassed and not stored", "path": "/proxy",
         "headers": ["X-Bypass: 1"],
         **cached("proxy_cache_bypass $http_x_bypass; proxy_no_cache $http_x_bypass;"),
         "accepts": BACKEND, "expect": {**proxied(100), "x-cache-status": "BYPASS"}},
        # Valid for a second: then one request updates it from the slow upstream, and the others get it stale.
        # Whether the check is the one that finds it expired depends on the second, so its status is not checked.
        {"feature": "proxy cache", "path": "/slow", "primed": True,
         "name": f"proxy_cache_use_stale updating, background update, upstream answering after "
                 f"{SLOW_UPSTREAM_DELAY * 1000:.0f} ms",
         **cached("proxy_cache_use_stale updating; proxy_cache_background_update on;", SLOW_UPSTREAM, "1s"),
         "accepts": SLOW_UPSTREAM, "expect": proxied(100)},
        # A new key each second, which all the connections ask for at once: one fetches it, the others wait.
        {"feature": "proxy cache", "path": "/slow",
         "name": f"proxy_cache_lock, a new key each second, upstream answering after {SLOW_UPSTREAM_DELAY * 1000:.0f} ms",
         **cached("proxy_cache_key $uri$sec; proxy_cache_lock on;", SLOW_UPSTREAM,
                  ahead=r'if ($msec ~ "^(\d+)") { set $sec $1; } '),
         "accepts": SLOW_UPSTREAM, "expect": proxied(100)},
    ),
    *group("tls",
        {"feature": "TLS", "name": "TLS, return, 64 connections", "path": "/return", "listen": "ssl",
         "server": CERT + RETURN, "expect": OK},
        {"feature": "TLS", "name": "TLS, full handshakes", "tool": "s_time", "path": "/return", "listen": "ssl",
         "server": CERT + RETURN, "expect": OK},
        {"feature": "TLS", "name": "TLS, resumed handshakes", "tool": "s_time", "resumed": True, "path": "/return",
         "listen": "ssl", "server": CERT + RETURN, "expect": OK},
        {"feature": "TLS", "name": "TLS, full handshakes with a client certificate", "tool": "s_time", "cert": "c",
         "path": "/return", "listen": "ssl",
         "server": CERT + "ssl_client_certificate /work/c.pem; ssl_verify_client on; "
                   'location = /return { add_header X-Verify $ssl_client_verify; return 200 "ok\\n"; }',
         "expect": {**OK, "x-verify": "SUCCESS"}},
        {"feature": "TLS", "name": "TLS, static 1m", "path": "/static/1m.bin", "listen": "ssl",
         "server": CERT + STATIC, "files": {"html/static/1m.bin": 1 << 20}, "expect": proxied(1 << 20)},
        {"feature": "TLS", "name": "TLS, full handshakes, ECDSA", "tool": "s_time", "path": "/return", "listen": "ssl",
         "server": EC + RETURN, "expect": OK},
        # From an intermediate authority, with a list of 10000 revoked certificates to look in.
        {"feature": "TLS", "name": "TLS, full handshakes with a client certificate, its chain and a CRL",
         "tool": "s_time", "cert": "client", "path": "/return", "listen": "ssl",
         "server": CERT + "ssl_client_certificate /work/clients.pem; ssl_crl /work/clients.crl; ssl_verify_depth 2; "
                   "ssl_verify_client on; "
                   'location = /return { '
                     'add_header X-Verify $ssl_client_verify; return 200 "ok\\n"; }',
         "expect": {**OK, "x-verify": "SUCCESS"}},
        {"feature": "TLS", "name": "TLS 1.2, resumed handshakes by session", "tool": "s_time", "resumed": True,
         "path": "/return", "listen": "ssl",
         "server": CERT + "ssl_protocols TLSv1.2; ssl_session_tickets off; ssl_session_cache shared:S:10m; " + RETURN,
         "expect": OK},
        # wrk resumes neither here, as nothing is kept; SNI names the certificate.
        {"feature": "TLS", "name": "TLS, full handshakes, the certificate named by a variable", "path": "/return",
         "close": True, "host": "localhost", "listen": "ssl",
         "server": "ssl_certificate /work/$ssl_server_name.crt; ssl_certificate_key /work/$ssl_server_name.key; "
                   "ssl_certificate_cache max=100; ssl_session_tickets off; "
                   "ssl_session_cache off; " + RETURN,
         "expect": {**OK, "connection": "close"}},
    ),
    *group("http2",
        {"feature": "HTTP/2", "name": "HTTP/2, one stream on each of 64 connections", "tool": "h2load", "streams": 1,
         "path": "/return", "listen": "ssl", "server": H2 + RETURN, "expect": OK2},
        {"feature": "HTTP/2", "name": "HTTP/2, 32 streams on each of 8 connections", "tool": "h2load",
         "connections": 8, "streams": 32, "path": "/return", "listen": "ssl", "server": H2 + RETURN, "expect": OK2},
        {"feature": "HTTP/2", "name": "HTTP/2, static 1m, 8 streams on each of 8 connections", "tool": "h2load",
         "connections": 8, "streams": 8, "path": "/static/1m.bin", "listen": "ssl", "server": H2 + STATIC,
         "files": {"html/static/1m.bin": 1 << 20}, "expect": {**OK2, "length": 1 << 20}},
        {"feature": "HTTP/2", "name": "HTTP/2, 64k POST proxied, 8 streams on each of 8 connections", "rounds": 9, "tool": "h2load",
         "connections": 8, "streams": 8, "post": True, "path": "/post", "listen": "ssl",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": H2 + "location / { proxy_pass http://backend; }", "accepts": BACKEND,
         "expect": {**OK2, "length": 100}},
        {"feature": "HTTP/2", "name": "HTTP/2, proxied, 32 streams on each of 8 connections", "tool": "h2load",
         "connections": 8, "streams": 32, "path": "/proxy", "listen": "ssl",
         "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
         "server": H2 + "location / { proxy_pass http://backend; }", "accepts": BACKEND,
         "expect": {**OK2, "length": 100}},
        # Every header in full and Huffman coded, as from a client that does not index.
        {"feature": "HTTP/2", "name": "HTTP/2, 18 headers in full, 32 streams on each of 8 connections",
         "tool": "h2load", "connections": 8, "streams": 32, "literal": True, "path": "/return", "listen": "ssl",
         "headers": HEADERS, "server": H2 + RETURN, "expect": OK2},
    ),
    *group("latency",
        {"feature": "operation", "name": "return, 64 connections, reloading", "path": "/return", "reload": True,
         "server": RETURN, "expect": OK},
        {"feature": "operation", "name": "TLS, return, reloading 200 servers with certificates", "path": "/return", "reload": True, "listen": "ssl",
         "server": CERT + RETURN,
         "http": " ".join(f"server {{ listen 127.0.0.1:@port@ ssl; server_name s{i}.test; {CERT} return 200 ok; }}" for i in range(200)),
         "expect": OK},
        # Whether what takes long holds up the others, which one thread serves.
        {"feature": "fairness", "name": "return, 16 connections, beside gzip of 5m", "kind": "beside", "path": "/return",
         "connections": 16, "beside": {"path": "/static/5m.txt", "connections": 4, "headers": ["Accept-Encoding: gzip"]},
         "server": "default_type text/plain; gzip on; gzip_types text/plain; " + RETURN + " " + STATIC,
         "files": {"html/static/5m.txt": (TEXT * 80)[:5 << 20]}, "expect": OK},
        {"feature": "fairness", "name": "TLS, return, 16 connections, beside full handshakes", "kind": "beside",
         "path": "/return", "connections": 16, "listen": "ssl", "beside": {"tool": "s_time", "path": "/return"},
         "server": CERT + RETURN, "expect": OK},
        {"feature": "first byte", "name": "first byte, return", "kind": "first", "path": "/return", "server": RETURN,
         "expect": OK},
        {"feature": "first byte", "name": "first byte, TLS", "kind": "first", "path": "/return", "listen": "ssl",
         "server": CERT + RETURN, "expect": OK},
        {"feature": "first byte", "name": "first byte, HTTP/2", "kind": "first", "tool": "h2load", "path": "/return",
         "listen": "ssl", "server": H2 + RETURN, "expect": OK2},
        # The rest of the answer comes 200 ms after its beginning.
        {"feature": "first byte", "name": "first byte, proxied as it comes", "kind": "first", "path": "/first",
         "server": f"location / {{ proxy_pass http://127.0.0.1:{SLOW_UPSTREAM}; proxy_buffering off; }}",
         "expect": {"status": 200, "length": 100}},
        # Long enough to show what grows.
        {"feature": "growth", "name": "return, a new connection per request, for 40 s", "path": "/return", "close": True,
         "seconds": 40, "rounds": 1, "server": RETURN, "expect": {**OK, "connection": "close"}},
        {"feature": "growth", "name": "HTTP/2, 32 streams on each of 8 connections, for 40 s", "tool": "h2load",
         "connections": 8, "streams": 32, "path": "/return", "listen": "ssl", "seconds": 40, "rounds": 1,
         "server": H2 + RETURN, "expect": OK2},
    ),
    *group("memory",
        *[{"feature": "slow clients", "kind": "memory", "client": "readers", "count": 50, **s} for s in (
            {"name": "static 10m, 50 slow readers", "path": "/static/10m.bin", "server": STATIC,
             "files": {"html/static/10m.bin": 10 << 20}, "expect": proxied(10 << 20)},
            {"name": "proxied 10m, 50 slow readers", "path": "/10m.bin",
             "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
             "server": "location / { proxy_pass http://backend; }", "expect": proxied(10 << 20)},
            {"name": "TLS, static 10m, 50 slow readers", "path": "/static/10m.bin", "tls": True, "listen": "ssl",
             "server": CERT + STATIC, "files": {"html/static/10m.bin": 10 << 20},
             "expect": proxied(10 << 20)},
            {"name": "HTTP/2, static 10m, 50 slow readers", "path": "/static/10m.bin", "tls": True, "h2": True,
             "tool": "h2load", "listen": "ssl", "server": H2 + STATIC,
             "files": {"html/static/10m.bin": 10 << 20},
             "expect": {"status": 200, "length": 10 << 20, "version": "2"}})],
        *[{"feature": "slow clients", "kind": "memory", "client": "uploaders", "count": 50, "post": True,
           "path": "/upload", "http": f"upstream backend {{ server 127.0.0.1:{BACKEND}; }}",
           "name": name, "server": f"client_max_body_size 0; location / {{ proxy_pass http://backend; {more} }}",
           "expect": proxied(100)} for name, more in (
               ("10m uploads, 50 slow senders", ""),
               ("10m uploads, 50 slow senders, proxy_request_buffering off", "proxy_request_buffering off;"))],
        *[{"feature": "connections", "kind": "memory", "client": "idle", "count": 1000, "path": "/return", **s} for s in (
            {"name": "1000 idle connections", "server": RETURN, "expect": OK},
            {"name": "TLS, 1000 idle connections", "tls": True, "listen": "ssl", "server": CERT + RETURN,
             "expect": OK},
            {"name": "HTTP/2, 1000 idle connections", "tls": True, "h2": True, "tool": "h2load", "listen": "ssl",
             "server": H2 + RETURN, "expect": OK2})],
    ),
]
