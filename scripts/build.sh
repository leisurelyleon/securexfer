#!/usr/bin/env bash
# Build the release binary.
set -euo pipefail

make
echo "Build complete. Binary at build/securexfer"
