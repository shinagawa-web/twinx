# The container image

`ghcr.io/shinagawa-web/twinx:<tag>` is laid out as the official `nginx` image is, with twinx in place of nginx. Each release tag publishes it (`.github/workflows/release.yml`, from `packaging/docker/Dockerfile`), and `latest` is the highest version tag. It is built for `linux/amd64` and `linux/arm64`, on Debian trixie-slim.

## What is in it

| Path | What it is |
|---|---|
| `/usr/sbin/twinx` | the server, started as `twinx -g "daemon off;"` |
| `/etc/nginx/nginx.conf` | the official image's main configuration, unchanged: `user nginx`, `worker_processes auto`, `pid /run/nginx.pid`, and `include /etc/nginx/conf.d/*.conf` |
| `/etc/nginx/conf.d/default.conf` | the official image's server on port 80, unchanged |
| `/etc/nginx/mime.types` | the MIME types |
| `/usr/share/nginx/html` | the default `index.html` and `50x.html` |
| `/var/log/nginx/access.log`, `error.log` | links to `/dev/stdout` and `/dev/stderr`, so `docker logs` shows both |
| `/var/cache/nginx` | the directories for request bodies and proxied responses written to disk |
| `/docker-entrypoint.sh`, `/docker-entrypoint.d/` | the official image's entrypoint and scripts |

The workers run as the user and group `nginx` (uid and gid 101). twinx reads `/etc/nginx/nginx.conf` without `-c`.

The entrypoint runs the scripts in `/docker-entrypoint.d/` before twinx starts, as in the official image: it adds `listen [::]:80` to an unchanged `default.conf` where IPv6 is available, writes templates with `envsubst`, and honours `NGINX_ENTRYPOINT_QUIET_LOGS`, `NGINX_ENTRYPOINT_LOCAL_RESOLVERS` and `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE`. Scripts added to `/docker-entrypoint.d/` run too.

## Running it

The default page on port 8080:

```
docker run -d --name web -p 8080:80 ghcr.io/shinagawa-web/twinx:<tag>
```

Your own pages, or your own server in place of the default one:

```
docker run -d -p 8080:80 -v /some/content:/usr/share/nginx/html:ro ghcr.io/shinagawa-web/twinx:<tag>
docker run -d -p 8080:80 -v $PWD/site.conf:/etc/nginx/conf.d/default.conf:ro ghcr.io/shinagawa-web/twinx:<tag>
```

Templates: each `/etc/nginx/templates/*.template` is written to `/etc/nginx/conf.d/` with its environment variables replaced, so a `default.conf.template` holding `listen ${NGINX_PORT};` becomes `default.conf` holding `listen 80;`:

```
docker run -d -p 8080:80 -v $PWD/templates:/etc/nginx/templates:ro -e NGINX_PORT=80 ghcr.io/shinagawa-web/twinx:<tag>
```

`NGINX_ENVSUBST_TEMPLATE_DIR`, `NGINX_ENVSUBST_TEMPLATE_SUFFIX`, `NGINX_ENVSUBST_OUTPUT_DIR` and `NGINX_ENVSUBST_FILTER` change this as they do in the official image.

Testing the configuration and reloading it in a running container:

```
docker exec web twinx -t
docker exec web twinx -s reload
```

`docker stop` sends SIGQUIT, and twinx finishes the requests in progress before it exits, as nginx does.

## What differs from the nginx image

- The command is `twinx`. There is no `nginx` and no `nginx-debug` in the image, so a `CMD` or `docker exec` that names them has to name `twinx` instead (`CMD ["twinx", "-g", "daemon off;"]`).
- Of the files the official image has in `/etc/nginx`, only `nginx.conf`, `conf.d/default.conf` and `mime.types` are here.
- twinx has no fastcgi, uwsgi or scgi module, no access module and no stream module, and refuses a configuration that uses their directives as nginx refuses a directive it does not know. In the official image's examples that means:
  - the commented-out `fastcgi_pass` location in `default.conf`, and the `deny all;` location after it;
  - `fastcgi_temp_path`, `uwsgi_temp_path` and `scgi_temp_path` in the docker-library example for running as a user other than root (`pid` and the other two temp paths are fine);
  - stream templates (`*.stream-template`), for which the entrypoint adds a `stream` block to `nginx.conf`.
