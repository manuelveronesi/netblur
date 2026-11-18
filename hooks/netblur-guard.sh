#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Starts the netblur guard with the first working Python interpreter.
# The guard runs locally and sends nothing anywhere.
dir=$(dirname "$0")
for p in python3 python py; do
  if "$p" -V >/dev/null 2>&1; then
    exec "$p" -I "$dir/netblur_guard.py"
  fi
done
echo "netblur guard: Python 3.9 or later not found, configuration files are not checked" >&2
exit 1
