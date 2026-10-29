#!/bin/sh
# Build the connect page in a pinned Node image. The server only needs Docker.
set -eu
cd "$(dirname "$0")"
docker run --rm -v "$PWD":/app -w /app node:22-alpine sh -c "npm ci && npm run build"
