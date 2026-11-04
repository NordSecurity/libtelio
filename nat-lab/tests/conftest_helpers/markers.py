"""Every guest a test is parametrized with must be declared by a marker of the same name.

The shard plan places a test by its markers and starts a shard's services by the same
keywords, so the two agree only as long as tests are marked. A test using
`ConnectionTag.VM_MAC` without `@pytest.mark.mac` is eligible for a `lite` shard, which
never started the mac guest, and fails there for a reason that looks like anything but a
missing marker.

Read from the parametrized values each item was collected with, which is where the tags
a test actually connects to come from. A tag named in a body is not counted: those are
mocks (`mock_connection.tag = ...`) and comparisons (`if tag == ConnectionTag.VM_MAC`),
and charging them to the test demands guests it never touches.
"""

import os
import pytest
from tests.utils.connection import ConnectionTag
from tests.utils.connection.docker_connection import (
    DOCKER_SERVICE_IDS,
    DOCKER_VM_SERVICE_IDS,
)
from typing import Dict, Iterator, List, Optional, Sequence, Set

# Service-name keywords that imply a capability, mirroring the lab's lab.yml. The
# playwright runner depends_on openwrt-gw-01, so it rides with openwrt.
CAPABILITY_BY_KEYWORD = {
    "windows": "windows",
    "mac": "mac",
    "android": "android",
    "nlx": "nlx",
    "fullcone": "fullcone",
    "openwrt": "openwrt",
    "playwright": "openwrt",
}

_MAX_DEPTH = 6
_SKIP_ENV = "NATLAB_SKIP_MARKER_CHECK"


def capability_of(tag: ConnectionTag) -> Optional[str]:
    """The capability this guest belongs to, if any.

    Derived from the service the tag names, falling back to the tag's own name: the
    fullcone, openwrt and nlx VM gateways have no service mapping.
    """
    service = DOCKER_SERVICE_IDS.get(tag) or DOCKER_VM_SERVICE_IDS.get(tag) or ""
    words = set(service.split("-")) | set(tag.name.lower().split("_"))
    for keyword, capability in CAPABILITY_BY_KEYWORD.items():
        if keyword in words:
            return capability
    return None


def _tags_in(value: object, depth: int = 0) -> Iterator[ConnectionTag]:
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, ConnectionTag):
        yield value
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _tags_in(item, depth + 1)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _tags_in(item, depth + 1)
    else:
        for attribute in getattr(value, "__dict__", {}).values():
            yield from _tags_in(attribute, depth + 1)


def required_capabilities(item: object) -> Set[str]:
    params: Dict[str, object] = (
        getattr(getattr(item, "callspec", None), "params", {}) or {}
    )
    tags = {tag for value in params.values() for tag in _tags_in(value)}
    return {c for c in (capability_of(tag) for tag in tags) if c}


def unmarked_guests(items: Sequence) -> List[str]:
    """One line per test parametrized with a guest it did not declare."""
    problems = []
    for item in items:
        marks = {mark.name for mark in item.iter_markers()}
        missing = sorted(required_capabilities(item) - marks)
        if missing:
            problems.append(
                f"{item.nodeid} uses {', '.join(missing)} but is not marked: "
                f"add @pytest.mark.{missing[0]}"
            )
    return problems


def check_marked_guests(items: Sequence) -> None:
    if os.environ.get(_SKIP_ENV):
        return
    problems = unmarked_guests(items)
    if problems:
        # UsageError rather than a bare raise: a collection hook that raises anything
        # else is reported as an INTERNALERROR with a traceback over the message
        raise pytest.UsageError(
            "these tests need a guest their markers do not declare, so a shard that "
            "skipped that guest would run them anyway:\n  "
            + "\n  ".join(problems)
            + f"\n(set {_SKIP_ENV}=1 to run regardless)"
        )
