from playwright.async_api import Locator, Page, expect
from tests.utils.luci.base_page import LuciPage
from tests.utils.luci.widgets import (
    cbi_button,
    cbi_dropdown,
    cbi_dropdown_input,
    cbi_dropdown_item,
    cbi_dropdown_selected,
    cbi_input,
    cbi_option_row,
    cbi_page_action_save,
    cbi_select,
    cbi_value_field,
    luci_notification,
)

SECTION = "config"
AUTH_SECTION = "auth"

STATUS_RUNNING = "Running"
STATUS_NOT_RUNNING = "Not running"
STATUS_AUTOSTART_DISABLED = "Not running (autostart disabled)"


class NordVpnLiteSettingsPage(LuciPage):
    URL = "/admin/services/nordvpnlite"

    def __init__(self, page: Page, base_url: str):
        super().__init__(page, base_url)
        self.token = cbi_input(page, AUTH_SECTION, "authentication_token")
        self.vpn_mode = cbi_select(page, SECTION, "vpn_mode")
        self.country = cbi_dropdown(page, SECTION, "vpn_country")
        self.country_row = cbi_option_row(page, self.country)
        self.server_address = cbi_input(page, SECTION, "server_address")
        self.server_address_row = cbi_option_row(page, self.server_address)
        self.server_public_key = cbi_input(page, SECTION, "server_public_key")
        self.server_public_key_row = cbi_option_row(page, self.server_public_key)
        self.get_country_list_button = cbi_button(page, "Get country list")
        self.save_button = cbi_page_action_save(page)
        self.service_status = cbi_value_field(page, "Service Status")
        self.start_button = cbi_button(page, "Start")
        self.restart_button = cbi_button(page, "Restart")
        self.stop_button = cbi_button(page, "Stop")
        self.enable_autostart_button = cbi_button(page, "Enable autostart")
        self.disable_autostart_button = cbi_button(page, "Disable autostart")
        self.get_status_button = cbi_button(page, "Get status")

    def notification(self, text: str) -> Locator:
        """Alert matching `text`, which may be the title or the message body."""
        return luci_notification(self.page, text)

    def runtime_field(self, name: str) -> Locator:
        """Runtime field: telio, ip, identifier, hostname, endpoint, state
        or public-key."""
        return self.page.locator(f"#nordvpnlite-runtime-{name}")

    def country_option(self, code: str) -> Locator:
        return cbi_dropdown_item(self.page, SECTION, "vpn_country", code)

    def selected_country(self) -> Locator:
        return cbi_dropdown_selected(self.page, SECTION, "vpn_country")

    async def select_vpn_mode(self, mode: str) -> None:
        """mode is one of: recommended, country, server."""
        await self.vpn_mode.select_option(mode)

    async def type_country_code(self, code: str) -> None:
        """Type a country code into the combobox free-text input."""
        await self.country.click()
        free_text = cbi_dropdown_input(self.page, SECTION, "vpn_country")
        await free_text.fill(code)
        await free_text.press("Enter")

    async def save(self) -> None:
        """Write the form to config.json. Never starts or restarts the daemon."""
        await self.save_button.click()

    async def wait_for_service_status(
        self, status: str, timeout: float = 30_000
    ) -> None:
        await expect(self.service_status).to_have_text(status, timeout=timeout)

    async def refresh_runtime_status(self) -> None:
        await self.get_status_button.click()
        await self.notification("Status loaded").first.wait_for(
            state="visible", timeout=10_000
        )

    async def wait_for_runtime_state(self, state: str, attempts: int = 6) -> None:
        """Refresh runtime status until the exit node reaches the given state."""
        for _ in range(attempts):
            await self.refresh_runtime_status()
            text = (await self.runtime_field("state").text_content() or "").strip()
            if text == state:
                return
            await self.page.wait_for_timeout(5_000)
        raise AssertionError(f"exit node never reached state '{state}'")
