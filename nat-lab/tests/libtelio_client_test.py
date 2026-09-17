from tests.libtelio_client import Client
from tests.utils.connection import TargetOS
from tests.utils.router import IPStack


class _StubConnection:
    target_os = TargetOS.Linux


class _StubNode:
    ip_stack = IPStack.IPv4


def test_allowlist_registered_after_client_start_is_visible():
    client = Client(_StubConnection(), _StubNode())  # type: ignore[arg-type]

    captured = client._allowed_errors  # pylint: disable=protected-access
    assert not captured

    client.allow_errors(["neptun::device.*Fatal read error"])

    assert [p.pattern for p in captured] == ["neptun::device.*Fatal read error"]


def test_allowlists_are_isolated_between_clients():
    first = Client(_StubConnection(), _StubNode())  # type: ignore[arg-type]
    second = Client(_StubConnection(), _StubNode())  # type: ignore[arg-type]

    first.allow_errors(["neptun::device.*Fatal read error"])
    assert not second._allowed_errors  # pylint: disable=protected-access
