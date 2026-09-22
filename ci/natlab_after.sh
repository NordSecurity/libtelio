#!/usr/bin/env bash
set -uo pipefail

dest="${CI_PROJECT_DIR:?}/natlab-collect/shard-${NATLAB_SHARD_INDEX:-1}"
mkdir -p "$dest"

for dir in logs coredumps; do
    [ -d "nat-lab/$dir" ] || continue
    cp -a "nat-lab/$dir" "$dest/" || echo "natlab_after: failed to copy nat-lab/$dir" >&2
done

exit 0
