#!/usr/bin/env sh
# Runs the ephemeral `ef` CLI: $EF_CLI (a path to tools/ef.mjs) if set,
# otherwise `ef` on PATH. Arguments pass through unchanged.
set -eu
if [ -n "${EF_CLI:-}" ]; then exec node "$EF_CLI" "$@"; fi
if command -v ef >/dev/null 2>&1; then exec ef "$@"; fi
echo "ef CLI not found. Install it (npm install -g github:bnap00/cf-ephemeral-share)" >&2
echo "or set EF_CLI=/path/to/cf-ephemeral-share/tools/ef.mjs" >&2
exit 127
