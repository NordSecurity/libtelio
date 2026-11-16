#!/usr/bin/env python3
"""Write the tests whose durations are new or changed against the published file.

    natlab_durations_delta.py compiled_test_durations.json shard_durations.json out.json
"""

import json
import sys
from pathlib import Path


def load(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    published, measured, out = (Path(a) for a in sys.argv[1:4])
    original = load(published)
    delta = {
        name: duration
        for name, duration in load(measured).items()
        if original.get(name) != duration
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(delta, f, indent=2)


if __name__ == "__main__":
    main()
