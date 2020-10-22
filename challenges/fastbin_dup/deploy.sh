#!/usr/bin/env bash

set -ex -o pipefail

PUBLIC_LISTEN_PORT=${1:-12345}

service docker start
docker build --tag fastbin_dup .
docker run --tty --interactive --publish ${PUBLIC_LISTEN_PORT}:4444 fastbin_dup
