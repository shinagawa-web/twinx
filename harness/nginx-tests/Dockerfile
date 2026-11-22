# The images nginx-tests run in: Perl for the tests and nginx-tests itself at a
# pinned commit, on top of the reference nginx 1.30.6. The "nginx" target keeps
# nginx to test it; the "twinx" target removes it, so twinx cannot hand the
# tests to the reference it is compared with.
FROM nginx@sha256:42c68eab6f7e22611786a9fe1d1c019e275c50185bd54b8f75dc2b9184322703 AS nginx

ARG NGINX_TESTS_COMMIT=cf2b5bf5f98f578a0a3da13c8c507c996f5f74fe

RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends perl libio-socket-ssl-perl libnet-ssleay-perl git ca-certificates \
 && git init -q /nginx-tests \
 && git -C /nginx-tests fetch -q --depth 1 https://github.com/nginx/nginx-tests.git "$NGINX_TESTS_COMMIT" \
 && git -C /nginx-tests checkout -q FETCH_HEAD \
 && rm -rf /nginx-tests/.git \
 && apt-get purge -y -q git >/dev/null && apt-get autoremove -y -q >/dev/null \
 && rm -rf /var/lib/apt/lists/*

COPY tap.pl /nginx-tests/tap.pl

# twinx's own tests, beside nginx-tests' files: behaviour nginx-tests does not
# check, written in its style and checked against nginx 1.30.6.
COPY extra/*.t /nginx-tests/

FROM nginx AS twinx
RUN rm -rf /usr/sbin/nginx /usr/sbin/nginx-debug /usr/lib/nginx /etc/nginx /docker-entrypoint.sh /docker-entrypoint.d
COPY rename.pl /tmp/rename.pl
RUN perl /tmp/rename.pl && rm /tmp/rename.pl
ENTRYPOINT []
