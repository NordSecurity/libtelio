import pytest
from playwright.async_api import expect
from tests.config import CORE_API_CREDENTIALS, STUN_SERVER, WG_SERVER, WG_SERVER_2
from tests.utils import stun
from tests.utils.connection import ConnectionTag
from tests.utils.luci.base_page import LuciPage, luci_base_url
from tests.utils.openwrt import (
    daemon_pid,
    is_autostart_enabled,
    read_uci_enabled,
    wait_for_new_daemon_pid,
)

OPENWRT_UI_TAGS = [
    pytest.param(ConnectionTag.VM_OPENWRT_GW_1, id="openwrt-25.12"),
]


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_settings_page_required_fields(
    clean_service_state, nordvpnlite_settings_page
):  # pylint: disable=unused-argument
    """
    Steps:
    1. Reset the gateway to the suite baseline config.
    2. Log into LuCI and open the NordVPN Lite settings page.
    3. Assert the form is pre-populated from the baseline: service enabled,
       token field visible, country mode with 'PL' selected, server fields
       hidden.
    4. Assert the service panel and Save & Apply button are present.
    """
    settings = nordvpnlite_settings_page
    await expect(settings.enabled).to_be_checked()
    await expect(settings.token).to_be_visible()
    await expect(settings.vpn_mode).to_have_value("country")
    await expect(settings.selected_country()).to_have_attribute("data-value", "PL")
    await expect(settings.server_address_row).to_be_hidden()
    await expect(settings.server_public_key_row).to_be_hidden()
    await expect(settings.service_status).to_be_visible()
    await expect(settings.save_apply_button).to_be_visible()


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
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


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_vpn_mode_switching(nordvpnlite_settings_page):
    """
    Steps:
    1. Open the settings page with a clean config (mode 'recommended').
    2. Switch to 'country' mode: country field appears, server fields hidden.
    3. Switch to 'server' mode: address + public key appear, country hides.
    4. Switch back to 'recommended': all mode-specific fields hide.
    """
    settings = nordvpnlite_settings_page

    await settings.select_vpn_mode("country")
    await expect(settings.country_row).to_be_visible()
    await expect(settings.server_address_row).to_be_hidden()
    await expect(settings.server_public_key_row).to_be_hidden()

    await settings.select_vpn_mode("server")
    await expect(settings.country_row).to_be_hidden()
    await expect(settings.server_address_row).to_be_visible()
    await expect(settings.server_public_key_row).to_be_visible()

    await settings.select_vpn_mode("recommended")
    await expect(settings.country_row).to_be_hidden()
    await expect(settings.server_address_row).to_be_hidden()
    await expect(settings.server_public_key_row).to_be_hidden()


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_country_code_auto_uppercase(nordvpnlite_settings_page):
    """
    Steps:
    1. Select 'country' mode and type a lowercase country code.
    2. Assert the widget normalized it to uppercase.
    """
    settings = nordvpnlite_settings_page
    await settings.select_vpn_mode("country")
    await settings.type_country_code("de")
    await expect(settings.selected_country()).to_have_attribute("data-value", "DE")


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_server_mode_requires_address(
    clean_service_state, nordvpnlite, nordvpnlite_settings_page
):  # pylint: disable=unused-argument
    """
    Steps:
    1. Select 'server' mode, fill only the public key, Save & Apply.
    2. Assert 'Save failed' (address missing) and the config unchanged.
    """
    settings = nordvpnlite_settings_page
    config_before = await nordvpnlite.read_config()

    await settings.select_vpn_mode("server")
    await settings.server_public_key.fill(str(WG_SERVER["public_key"]))
    await settings.save_and_apply()
    await expect(settings.notification("Save failed")).to_be_visible()
    assert await nordvpnlite.read_config() == config_before


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_disable_service_via_ui(
    clean_service_state, gateway_connection, nordvpnlite_settings_page
):  # pylint: disable=unused-argument
    """
    Steps:
    1. Uncheck 'Enable service' and Save & Apply.
    2. Assert the status shows 'Stopped (service disabled)'.
    3. Assert Start, Restart and Stop are all disabled.
    4. Assert the UCI flag was written (nordvpnlite.settings.enabled == 0).
    """
    settings = nordvpnlite_settings_page

    await settings.enabled.uncheck()
    await settings.save_and_apply()

    await settings.wait_for_service_status("Stopped (service disabled)")
    await expect(settings.start_button).to_be_disabled()
    await expect(settings.restart_button).to_be_disabled()
    await expect(settings.stop_button).to_be_disabled()
    assert await read_uci_enabled(gateway_connection) == "0"


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_save_persists_country_config(
    clean_service_state, nordvpnlite, nordvpnlite_settings_page
):  # pylint: disable=unused-argument
    """
    Steps:
    1. Uncheck 'Enable service' (so Save & Apply does not start the daemon),
       fill token, select country mode, type 'de'.
    2. Save & Apply (page just reloads, no daemon start).
    3. Assert /etc/nordvpnlite/config.json contents over SSH.
    4. Assert the reloaded form is pre-populated from the saved config.
    """
    settings = nordvpnlite_settings_page

    await settings.enabled.uncheck()
    await settings.token.fill(CORE_API_CREDENTIALS["password"])
    await settings.select_vpn_mode("country")
    await settings.type_country_code("de")
    await settings.save_and_apply()

    # the disabled status appears only after the post-save reload, proving
    # both RPC writes completed before we read files over SSH
    await settings.wait_for_service_status("Stopped (service disabled)")

    config = await nordvpnlite.read_config()
    assert config["authentication_token"] == CORE_API_CREDENTIALS["password"]
    assert config["vpn"] == {"country": "DE"}

    await expect(settings.enabled).not_to_be_checked()
    await expect(settings.vpn_mode).to_have_value("country")
    await expect(settings.selected_country()).to_have_attribute("data-value", "DE")


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_save_persists_server_config(
    clean_service_state, nordvpnlite, nordvpnlite_settings_page
):  # pylint: disable=unused-argument
    """
    Steps:
    1. Uncheck 'Enable service', fill token, select server mode,
       fill address + public key.
    2. Save & Apply.
    3. Assert config.json holds the server block; the reloaded form shows it.
    """
    settings = nordvpnlite_settings_page

    await settings.enabled.uncheck()
    await settings.token.fill(CORE_API_CREDENTIALS["password"])
    await settings.select_vpn_mode("server")
    await settings.server_address.fill(str(WG_SERVER["ipv4"]))
    await settings.server_public_key.fill(str(WG_SERVER["public_key"]))
    await settings.save_and_apply()

    await settings.wait_for_service_status("Stopped (service disabled)")

    config = await nordvpnlite.read_config()
    assert config["vpn"] == {
        "server": {
            "address": str(WG_SERVER["ipv4"]),
            "public_key": str(WG_SERVER["public_key"]),
        }
    }
    await expect(settings.vpn_mode).to_have_value("server")
    await expect(settings.server_address).to_have_value(str(WG_SERVER["ipv4"]))
    await expect(settings.server_public_key).to_have_value(str(WG_SERVER["public_key"]))


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_get_country_list(
    trusted_core_api_cert, nordvpnlite_settings_page
):  # pylint: disable=unused-argument
    """
    Steps:
    1. Trust the natlab core-api CA in the VM's system store (fixture).
    2. Select 'country' mode and click 'Get country list'.
    3. Assert the 'Countries loaded' notification.
    4. Open the dropdown and assert the mocked countries are offered.
    5. Choose Germany and assert it becomes the selected value.
    """
    settings = nordvpnlite_settings_page
    await settings.select_vpn_mode("country")
    await settings.get_country_list_button.click()
    await expect(settings.notification("Countries loaded")).to_be_visible(
        timeout=10_000
    )

    await settings.country.click()
    await expect(settings.country_option("PL")).to_have_text("Poland (PL)")
    await expect(settings.country_option("DE")).to_have_text("Germany (DE)")
    await settings.country_option("DE").click()
    await expect(settings.selected_country()).to_have_attribute("data-value", "DE")


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_service_start_stop_restart(
    prepare_nordvpnlite_env, nordvpnlite, nordvpnlite_settings_page
):
    """
    Steps:
    1. Seed the gateway (PL preset + core-api credentials), service stopped.
    2. Assert the initial panel: 'Stopped', only Start enabled.
    3. Change the country to DE in the form without saving it explicitly, then
       click Start. Start must persist the pending edit before launching the
       daemon.
    4. Assert 'Running', button states flipped, and config.json now holds DE.
    5. Refresh runtime status until the exit node is connected; assert the
       DE server runtime fields.
    6. Note the daemon PID and click Restart; assert a new daemon process
       replaced it and the panel shows 'Running' again.
    7. Click Stop; assert 'Stopped'.
    """
    settings = nordvpnlite_settings_page
    gateway = prepare_nordvpnlite_env

    await settings.wait_for_service_status("Stopped")
    await expect(settings.start_button).to_be_enabled()
    await expect(settings.restart_button).to_be_disabled()
    await expect(settings.stop_button).to_be_disabled()

    assert (await nordvpnlite.read_config())["vpn"] == {"country": "pl"}
    await expect(settings.vpn_mode).to_have_value("country")
    await settings.type_country_code("de")

    await settings.start_button.click()
    await settings.wait_for_service_status("Running")
    await expect(settings.start_button).to_be_disabled()
    await expect(settings.restart_button).to_be_enabled()
    await expect(settings.stop_button).to_be_enabled()

    assert (await nordvpnlite.read_config())["vpn"] == {"country": "DE"}

    await settings.wait_for_runtime_state("connected")
    await expect(settings.runtime_field("telio")).to_have_text("Yes")
    await expect(settings.runtime_field("ip")).not_to_be_empty()
    await expect(settings.runtime_field("endpoint")).to_contain_text(
        str(WG_SERVER_2["ipv4"])
    )
    await expect(settings.runtime_field("public-key")).to_have_text(
        str(WG_SERVER_2["public_key"])
    )

    pid_before = await daemon_pid(gateway)
    assert pid_before, "daemon PID not found while the service is running"
    await settings.restart_button.click()
    await wait_for_new_daemon_pid(gateway, pid_before)
    await settings.wait_for_service_status("Running")

    await settings.stop_button.click()
    await settings.wait_for_service_status("Stopped")


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_disable_autostart(
    prepare_nordvpnlite_env, nordvpnlite_settings_page
):
    """
    Steps:
    1. Baseline: autostart enabled, service stopped.
    2. Click 'Disable autostart'; assert the status text and the init
       script's enabled state over SSH.
    3. Click 'Enable autostart'; assert both flipped back.
    """
    settings = nordvpnlite_settings_page
    gateway = prepare_nordvpnlite_env

    assert await is_autostart_enabled(gateway)
    await expect(settings.disable_autostart_button).to_be_enabled()
    await expect(settings.enable_autostart_button).to_be_disabled()

    await settings.disable_autostart_button.click()
    await settings.wait_for_service_status("Stopped (autostart disabled)")
    assert not await is_autostart_enabled(gateway)

    await settings.enable_autostart_button.click()
    await settings.wait_for_service_status("Stopped")
    assert await is_autostart_enabled(gateway)


@pytest.mark.asyncio
@pytest.mark.openwrt
@pytest.mark.openwrt_ui
@pytest.mark.parametrize("gw_tag", OPENWRT_UI_TAGS, indirect=True)
async def test_nordvpnlite_save_apply_connects_to_selected_country(
    prepare_nordvpnlite_env, nordvpnlite_settings_page
):
    """
    Steps:
    1. Seed the gateway with the PL country preset (service stopped).
    2. In the UI change the country to DE and Save & Apply; the UI writes the
       config, restarts the service and polls until the exit node connects.
    3. Assert the service is Running and the runtime panel reaches 'connected'.
    4. Assert the router egresses via the DE VPN server
       (STUN-reported IP == WG_SERVER_2).
    """
    settings = nordvpnlite_settings_page
    gateway = prepare_nordvpnlite_env

    await expect(settings.vpn_mode).to_have_value("country")
    await settings.type_country_code("de")
    await settings.save_and_apply()

    await settings.wait_for_service_status("Running")
    await settings.wait_for_runtime_state("connected")
    await expect(settings.runtime_field("telio")).to_have_text("Yes")

    gw_ip = await stun.get(gateway, STUN_SERVER)
    assert gw_ip == WG_SERVER_2["ipv4"], (
        f"OpenWRT gateway egress IP is {gw_ip},"
        f" expected DE VPN server {WG_SERVER_2['ipv4']}"
    )
