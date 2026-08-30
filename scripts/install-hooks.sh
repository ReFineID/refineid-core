#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
# Enable this repository's shared git hooks (one-time, per clone).
#
# core.hooksPath is a local setting git does not apply automatically on clone,
# so each working copy runs this once. It points git at the tracked .githooks
# directory, activating the once-a-day version date stamp and the mandatory
# quality gates: fast checks at commit, the full floor at push.
set -eu

root=$(git rev-parse --show-toplevel)
chmod +x "$root/.githooks/"* "$root/scripts/"*.sh
git -C "$root" config core.hooksPath .githooks
echo "git hooks enabled: core.hooksPath = .githooks"
