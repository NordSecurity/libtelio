import asyncio
from contextlib import contextmanager
from typing import List, Dict, Set, Iterator


class OutputCapture:
    def __init__(self, what: str) -> None:
        self.what: str = what
        self.lines: List[str] = []

    def handle_output(self, line: str) -> None:
        if self.what in line:
            self.lines.append(line)


class OutputNotifier:
    def __init__(self, case_sensitive=True) -> None:
        self._output_events: Dict[str, List[asyncio.Event]] = {}
        self._captures: Set[OutputCapture] = set()
        self._case_sensitive = case_sensitive

    def notify_output(self, what: str, event: asyncio.Event) -> None:
        if not self._case_sensitive:
            what = what.lower()

        if what not in self._output_events:
            self._output_events[what] = [event]
        else:
            self._output_events[what].append(event)

    @contextmanager
    def capture_output(self, what: str) -> Iterator[OutputCapture]:
        capture = OutputCapture(what)
        self._captures.add(capture)
        try:
            yield capture
        finally:
            self._captures.remove(capture)

    def handle_output(self, line) -> bool:
        if not self._case_sensitive:
            line = line.lower()

        hit_list: Set[str] = set(
            filter(lambda what: what in line, self._output_events.keys())
        )

        for what in hit_list:
            events = self._output_events.pop(what)
            for event in events:
                event.set()

        for capture in self._captures:
            capture.handle_output(line)

        return len(hit_list) > 0
