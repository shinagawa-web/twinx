#!/usr/bin/env bash
# Setup script for the Claude Code on the web environment that runs the loop.
# It runs as root before each session (or once, when the environment is cached).
# Rust and Docker are preinstalled there; this pulls the pinned nginx image so
# that it is part of the cached environment.
set -euo pipefail

if ! docker info >/dev/null 2>&1; then
  nohup dockerd >/tmp/dockerd.log 2>&1 &
  for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
fi
docker pull nginx@sha256:42c68eab6f7e22611786a9fe1d1c019e275c50185bd54b8f75dc2b9184322703
# The image the judge builds twinx in (harness/run_tests.py, RUST_IMAGE).
docker pull rust@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37
cargo --version
python3 --version
