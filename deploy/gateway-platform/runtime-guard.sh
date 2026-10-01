#!/bin/sh
set -eu
# K1 is source/coding authority only. An environment variable, a Compose profile,
# or a direct invocation must not authorize startup. The separate activation
# gate must replace this deny-only guard with its reviewed verifier.
echo 'runtime_apply_unauthorized: separate activation gate required' >&2
exit 78
