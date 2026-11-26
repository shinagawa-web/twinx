#!/bin/sh
# usage: check.sh <image>
set -eu
page=$(dirname "$0")/html/index.html
id=$(docker run -d -p 127.0.0.1::80 "$1")
trap 'docker rm -f "$id" >/dev/null' EXIT
port=$(docker port "$id" 80/tcp | head -n 1 | sed 's/.*://')
body=$(mktemp)
for _ in $(seq 50); do
    code=$(curl -s -o "$body" -w '%{http_code}' "http://127.0.0.1:$port/") && break
    sleep 0.2
done
if [ "${code:-}" = 200 ] && cmp -s "$body" "$page"; then
    echo "GET / answered 200 with the default page"
    exit 0
fi
echo "GET / answered ${code:-nothing}:" >&2
head -c 2000 "$body" >&2 || true
echo "--- docker logs" >&2
docker logs "$id" >&2 2>&1 || true
exit 1
