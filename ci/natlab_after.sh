#!/usr/bin/env bash
set -uo pipefail

shard="${NATLAB_SHARD_INDEX:-1}"
dest="${CI_PROJECT_DIR:?}/natlab-collect/shard-${shard}"
mkdir -p "$dest"

for dir in logs coredumps; do
    [ -d "nat-lab/$dir" ] || continue
    cp -a "nat-lab/$dir" "$dest/" || echo "natlab_after: failed to copy nat-lab/$dir" >&2
done

# the delta against the published file, as run_local.py used to compute it; the shard
# name keeps the nine files distinct for ci/test_durations.py to compile
if [ -f nat-lab/shard_durations.json ]; then
    python3 ci/natlab_durations_delta.py \
        nat-lab/compiled_test_durations.json \
        nat-lab/shard_durations.json \
        "$dest/node_${shard}_durations.json" \
        || echo "natlab_after: durations delta failed" >&2
fi

exit 0
