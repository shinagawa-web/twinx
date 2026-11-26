# Built from the repository's root, with the release binaries in dist/ as the
# release workflow names them.
ARG TARGETARCH

FROM scratch AS twinx-amd64
COPY dist/twinx-*-x86_64-linux-gnu /twinx

FROM scratch AS twinx-arm64
COPY dist/twinx-*-aarch64-linux-gnu /twinx

FROM twinx-${TARGETARCH} AS twinx

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

LABEL org.opencontainers.image.source="https://github.com/shinagawa-web/twinx"

# twinx looks under /usr/local/twinx/ for what nginx is built to find in
# /etc/nginx, /var/log/nginx and /var/cache/nginx.
RUN set -x \
    && groupadd --system --gid 101 nginx \
    && useradd --system --gid nginx --no-create-home --home /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
    && apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y ca-certificates gettext-base curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/nginx/conf.d /var/log/nginx /usr/share/nginx/html /usr/share/twinx /usr/local/twinx /docker-entrypoint.d \
    && install -d -o nginx -g nginx -m 700 /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
    && ln -s /etc/nginx /usr/local/twinx/conf \
    && ln -s /var/log/nginx /usr/local/twinx/logs \
    && ln -s /var/cache/nginx/client_temp /usr/local/twinx/client_body_temp \
    && ln -s /var/cache/nginx/proxy_temp /usr/local/twinx/proxy_temp \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# nginx/ holds pkg-oss's debian/nginx.conf and debian/nginx.default.conf
# unchanged (github.com/nginx/pkg-oss at 2bd07c53a97815f0b45fc02b155582eec187dfb5),
# which the official image installs from the nginx package.
COPY packaging/docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY packaging/docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY conf/mime.types /etc/nginx/mime.types
COPY packaging/docker/html/ /usr/share/nginx/html/
COPY packaging/docker/nginx/LICENSE /usr/share/doc/twinx/pkg-oss.LICENSE
COPY packaging/docker/entrypoint/LICENSE /usr/share/doc/twinx/docker-nginx.LICENSE
RUN md5sum /etc/nginx/conf.d/default.conf | cut -d' ' -f1 > /usr/share/twinx/default.conf.md5

COPY packaging/docker/entrypoint/docker-entrypoint.sh /
COPY packaging/docker/entrypoint/10-listen-on-ipv6-by-default.sh /docker-entrypoint.d
COPY packaging/docker/entrypoint/15-local-resolvers.envsh /docker-entrypoint.d
COPY packaging/docker/entrypoint/20-envsubst-on-templates.sh /docker-entrypoint.d
COPY packaging/docker/entrypoint/30-tune-worker-processes.sh /docker-entrypoint.d
COPY --from=twinx --chmod=755 /twinx /usr/sbin/twinx
ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80

STOPSIGNAL SIGQUIT

CMD ["twinx", "-g", "daemon off;"]
