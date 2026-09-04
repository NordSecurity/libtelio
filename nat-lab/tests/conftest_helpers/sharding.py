"""Deterministic assignment of collected tests to CI shards.

Every shard runs this same code over the same inputs and derives the same
assignment, then keeps its own slice - so the shards need no coordination and
nothing has to be recorded in the repository.

Inputs, all identical across shards:
  * the collected items, after pytest has applied `-m`
  * $NATLAB_SHARD_PLAN - the shard topology, set by .gitlab-ci.yml
  * compiled_test_durations.json - published by a previous pipeline

A test's requirements are its markers; a shard's capabilities are whatever it
did not skip. The marker names are deliberately the same strings natlab.py
skips by (see `_resolve_skip_keywords`), so eligibility is a set intersection
and there is no mapping table to keep in sync.
"""

import json
import os
import statistics
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

# Markers that mean "this test needs a service some shards do not start". Every
# other marker (ipv4, moose, linux_native, ...) says nothing about placement.
CAPABILITIES = frozenset({"windows", "mac", "android", "nlx", "fullcone", "openwrt"})

DURATIONS_FILE = "compiled_test_durations.json"


@dataclass(frozen=True)
class Shard:
    """One CI job instance: what it will not start, and what it costs to boot."""

    name: str
    skip: frozenset
    startup_seconds: float


def parse_plan(raw: str) -> List[Shard]:
    """Expand the plan JSON into one Shard per job instance.

    `count` repeats a class in place, so the resulting list index is the
    1-based CI_NODE_INDEX minus one - the same on every shard.
    """
    shards: List[Shard] = []
    for entry in json.loads(raw):
        skip = frozenset(entry.get("skip", []))
        unknown = skip - CAPABILITIES
        if unknown:
            raise ValueError(
                f"shard {entry.get('name')!r} skips unknown capabilities:"
                f" {sorted(unknown)} (known: {sorted(CAPABILITIES)})"
            )
        for _ in range(int(entry.get("count", 1))):
            shards.append(
                Shard(
                    name=str(entry["name"]),
                    skip=skip,
                    startup_seconds=float(entry.get("startup_seconds", 0)),
                )
            )
    if not shards:
        raise ValueError("NATLAB_SHARD_PLAN expanded to zero shards")
    return shards


def load_durations(directory: str = ".") -> Dict[str, float]:
    """Per-test seconds from the published durations, or {} when unavailable.

    $NATLAB_DURATIONS_FILE overrides the path, so a caller outside nat-lab can
    point this at the same file it reports from.
    """
    path = os.environ.get("NATLAB_DURATIONS_FILE", "").strip() or os.path.join(
        directory, DURATIONS_FILE
    )
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: float(v) for k, v in data.items()}


def requirements(item) -> frozenset:
    """The capability markers a single test carries."""
    return frozenset(mark.name for mark in item.iter_markers()) & CAPABILITIES


def unserved(shards: Sequence[Shard]) -> List[str]:
    """Capabilities every shard skips, so tests needing them have nowhere to run.

    Only single capabilities: whether a *combination* matters depends on which
    tests exist, which the plan cannot know. A test needing an unservable
    combination fails loudly at collection time instead.
    """
    return sorted(
        capability
        for capability in CAPABILITIES
        if all(capability in shard.skip for shard in shards)
    )


def assign(items: Sequence, shards: Sequence[Shard], durations: Dict[str, float]):
    """Distribute items across shards. Returns one list of items per shard.

    Constrained-LPT: tests that few shards can run are placed first, longest
    first within that, so the VM tests claim their shards before the movable
    docker-only ones fill whatever is left. The sort key ends in nodeid, making
    the order total - two shards cannot disagree because of a tie.
    """
    default = statistics.median(durations.values()) if durations else 1.0

    def seconds(item) -> float:
        return durations.get(item.nodeid, default)

    eligible: Dict[str, List[int]] = {}
    for item in items:
        needs = requirements(item)
        eligible[item.nodeid] = [
            i for i, shard in enumerate(shards) if not (needs & shard.skip)
        ]
        if not eligible[item.nodeid]:
            raise RuntimeError(
                f"no shard can run {item.nodeid}: it needs {sorted(needs)},"
                " and every shard skips at least one of those."
                " Add a shard that starts them, or the test cannot run in CI."
            )

    load = [shard.startup_seconds for shard in shards]
    buckets: List[List] = [[] for _ in shards]

    ordered = sorted(
        items,
        key=lambda it: (len(eligible[it.nodeid]), -seconds(it), it.nodeid),
    )
    for item in ordered:
        candidates = eligible[item.nodeid]
        target = min(candidates, key=lambda i: (load[i], i))
        load[target] += seconds(item)
        buckets[target].append(item)

    return buckets, load


def plan_from_env() -> Optional[Tuple[List[Shard], int]]:
    """(shards, zero-based index) when CI asked for sharding, else None.

    Absent or incomplete configuration means "run everything", which is what a
    developer running the suite locally wants.
    """
    raw = os.environ.get("NATLAB_SHARD_PLAN", "").strip()
    index = os.environ.get("CI_NODE_INDEX", "").strip()
    if not raw or not index:
        return None

    shards = parse_plan(raw)
    position = int(index) - 1
    if not 0 <= position < len(shards):
        raise ValueError(
            f"CI_NODE_INDEX={index} is outside the {len(shards)} shards in"
            " NATLAB_SHARD_PLAN - `parallel:` and the plan disagree"
        )
    return shards, position


def select_for_this_shard(items: Sequence, durations_dir: str = "."):
    """Split items into (mine, other_shards'). Both empty-handed when unsharded."""
    plan = plan_from_env()
    if plan is None:
        return list(items), [], None

    shards, position = plan
    durations = load_durations(durations_dir)
    buckets, load = assign(items, shards, durations)

    mine = buckets[position]
    keep = {item.nodeid for item in mine}
    others = [item for item in items if item.nodeid not in keep]
    summary = (
        f"shard {position + 1}/{len(shards)} ({shards[position].name}): "
        f"{len(mine)} of {len(items)} tests, ~{load[position] / 60:.1f} min predicted"
        f"{'' if durations else ' (no durations file - balancing by count)'}"
    )
    return mine, others, summary
