import pytest
import pytest_asyncio
from contextlib import AsyncExitStack
from pathlib import Path
from tests.config import CORE_API_CA_CERTIFICATE_PATH
from tests.nordvpnlite import (
    CONFIG_PRESETS,
    Config,
    ConfigPresetName,
    NordVpnLite,
    Paths,
)
from tests.utils.connection import Connection
from tests.utils.connection_util import new_connection_by_tag
from tests.utils.luci.base_page import luci_base_url
from tests.utils.luci.nordvpnlite_page import NordVpnLiteSettingsPage
from tests.utils.playwright_browser import remote_page, save_failure_screenshot
from tests.utils.process import ProcessExecError

CA_BUNDLE_PATH = "/etc/ssl/certs/ca-certificates.crt"
NORDVPNLITE_SERVICE_CONFIG_PATH = Path("/etc/nordvpnlite/config.json")


@pytest_asyncio.fixture
async def browser_page(request):
    """Per-test Playwright Page

    On test failure, saves a screenshot under logs/<test_name>/<test_name>.png.
    UI test fixtures should compose on top of this fixture so screenshot-on-
    failure happens automatically.

    """
    async with remote_page() as page:
        try:
            yield page
        finally:
            await save_failure_screenshot(page, request)


@pytest.fixture
def gw_tag(request):
    return request.param


@pytest_asyncio.fixture
async def gateway_connection(gw_tag):  # pylint: disable=redefined-outer-name
    async with new_connection_by_tag(gw_tag) as connection:
        yield connection


@pytest_asyncio.fixture
async def nordvpnlite(gateway_connection):  # pylint: disable=redefined-outer-name
    """NordVpnLite handle bound to the config path the init script uses."""
    async with AsyncExitStack() as exit_stack:
        config = Config(
            CONFIG_PRESETS[ConfigPresetName.VPN_OPENWRT_UCI_PL],
            config_path=NORDVPNLITE_SERVICE_CONFIG_PATH,
            paths=Paths(exec_path=Path("nordvpnlite")),
        )
        yield NordVpnLite(gateway_connection, exit_stack, config=config)


@pytest_asyncio.fixture
async def nordvpnlite_settings_page(
    browser_page, gw_tag
):  # pylint: disable=redefined-outer-name
    settings = NordVpnLiteSettingsPage(browser_page, luci_base_url(gw_tag))
    await settings.login()
    await settings.open()
    yield settings


async def _run_quiet(connection: Connection, cmd: list[str]) -> None:
    try:
        await connection.create_process(cmd).execute()
    except ProcessExecError:
        pass


async def _reset_service_state(
    nordvpnlite: NordVpnLite,  # pylint: disable=redefined-outer-name
) -> None:
    """Reset the gateway to the suite baseline: natlab preset config,
    service stopped, UCI enabled flag on, autostart on."""
    connection = nordvpnlite.connection
    await nordvpnlite.clean_up()
    await nordvpnlite.save_config()
    await _run_quiet(
        connection,
        [
            "sh",
            "-c",
            "uci -q set nordvpnlite.settings.enabled='1'"
            " && uci -q commit nordvpnlite",
        ],
    )
    await _run_quiet(connection, ["/etc/init.d/nordvpnlite", "enable"])


@pytest_asyncio.fixture
async def clean_service_state(nordvpnlite):  # pylint: disable=redefined-outer-name
    await _reset_service_state(nordvpnlite)
    yield
    await _reset_service_state(nordvpnlite)


@pytest_asyncio.fixture
async def trusted_core_api_cert(
    gateway_connection,
):  # pylint: disable=redefined-outer-name
    """Temporarily add the natlab core-api CA to the VM's system trust store."""
    backup = "/tmp/ca-certificates.crt.natlab-backup"
    await gateway_connection.create_process(["cp", CA_BUNDLE_PATH, backup]).execute()
    await gateway_connection.create_process([
        "sh",
        "-c",
        "sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p'"
        f" {CORE_API_CA_CERTIFICATE_PATH} >> {CA_BUNDLE_PATH}",
    ]).execute()
    yield
    await gateway_connection.create_process(["mv", backup, CA_BUNDLE_PATH]).execute()


@pytest_asyncio.fixture
async def prepare_nordvpnlite_env(
    nordvpnlite, clean_service_state
):  # pylint: disable=redefined-outer-name,unused-argument
    """Seed core-api credentials and VPN server keys for the baseline config."""
    await nordvpnlite.request_credentials_from_core()
    yield nordvpnlite.connection
