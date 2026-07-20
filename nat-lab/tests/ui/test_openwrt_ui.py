import pytest
import pytest_asyncio
from playwright.async_api import expect
from tests.utils.connection import ConnectionTag
from tests.utils.luci.base_page import LuciPage, luci_base_url
from tests.utils.luci.nordvpnlite_page import NordVpnLiteSettingsPage

OPENWRT_UI_TAGS = [
    pytest.param(ConnectionTag.VM_OPENWRT_GW_1, id="openwrt-25.12"),
]


@pytest_asyncio.fixture
async def nordvpnlite_settings(browser_page, request):
    gw_tag = request.param
    settings = NordVpnLiteSettingsPage(browser_page, luci_base_url(gw_tag))
    await settings.login()
    await settings.open()
    yield settings


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("nordvpnlite_settings", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_settings_required_fields(
    nordvpnlite_settings,
):  # pylint: disable=redefined-outer-name
    """
    Steps:
    1. Log into LuCI and open the NordVPN Lite settings page.
    2. Assert the Country Code field is visible.
    """
    await expect(nordvpnlite_settings.vpn).to_be_visible()


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS)
async def test_nordvpnlite_reachable_via_services_menu(browser_page, gw_tag):
    """
    Steps:
    1. Log into LuCI.
    2. Hover the Services top-bar menu and click NordVPN Lite.
    3. Assert the URL lands on /admin/services/nordvpnlite.
    """
    luci = LuciPage(browser_page, luci_base_url(gw_tag))
    await luci.login()
    await luci.click_menu_item("Services", "NordVPN Lite")
    assert browser_page.url.endswith("/admin/services/nordvpnlite")
