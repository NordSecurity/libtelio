from tests.conftest_helpers.markers import (
    capability_of,
    required_capabilities,
    unmarked_guests,
)
from tests.helpers import SetupParameters
from tests.utils.connection import ConnectionTag


class FakeItem:
    def __init__(self, params, marks):
        self.nodeid = "tests/test_x.py::test_y"
        self.callspec = type("Spec", (), {"params": params})()
        self._marks = marks

    def iter_markers(self):
        return [type("M", (), {"name": m})() for m in self._marks]


# a table rather than parametrize: the check under test reads an item's parameters,
# and a test parametrized over guest tags it never connects to would trip it
EXPECTED = [
    (ConnectionTag.VM_MAC, "mac"),
    (ConnectionTag.DOCKER_MAC_GW_1, "mac"),
    (ConnectionTag.VM_WINDOWS_1, "windows"),
    (ConnectionTag.DOCKER_WINDOWS_VM_1, "windows"),
    (ConnectionTag.VM_LINUX_NLX_1, "nlx"),
    (ConnectionTag.VM_LINUX_FULLCONE_GW_1, "fullcone"),
    (ConnectionTag.VM_OPENWRT_GW_1, "openwrt"),
    # it depends_on openwrt-gw-01, so it boots the OpenWrt VM either way
    (ConnectionTag.DOCKER_PLAYWRIGHT_RUNNER_1, "openwrt"),
    (ConnectionTag.DOCKER_CONE_CLIENT_1, None),
    (ConnectionTag.DOCKER_OPEN_INTERNET_CLIENT_DUAL_STACK, None),
]


def test_capability_of_a_tag():
    assert [(tag.name, capability_of(tag)) for tag, _ in EXPECTED] == [
        (tag.name, capability) for tag, capability in EXPECTED
    ]


def test_tags_are_found_through_setup_parameters():
    item = FakeItem(
        {"setup": [SetupParameters(connection_tag=ConnectionTag.VM_MAC)]}, []
    )
    assert required_capabilities(item) == {"mac"}


def test_an_unmarked_guest_is_reported():
    item = FakeItem({"tag": ConnectionTag.VM_WINDOWS_1}, ["asyncio"])
    problems = unmarked_guests([item])
    assert len(problems) == 1
    assert "add @pytest.mark.windows" in problems[0]


def test_a_marked_guest_is_accepted():
    item = FakeItem({"tag": ConnectionTag.VM_WINDOWS_1}, ["windows"])
    assert not unmarked_guests([item])


def test_a_docker_only_test_needs_no_marker():
    item = FakeItem({"tag": ConnectionTag.DOCKER_CONE_CLIENT_1}, [])
    assert not unmarked_guests([item])
