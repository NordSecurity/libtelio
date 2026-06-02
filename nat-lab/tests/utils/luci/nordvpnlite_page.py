from playwright.async_api import Page
from tests.utils.luci.base_page import LuciPage
from tests.utils.luci.widgets import cbi_button_save, cbi_input


class NordVpnLiteSettingsPage(LuciPage):
    URL = "/admin/services/nordvpnlite"

    def __init__(self, page: Page, base_url: str):
        super().__init__(page, base_url)
        self.token = cbi_input(page, "config", "authentication_token")
        self.vpn = cbi_input(page, "config", "vpn")
        self.save_button = cbi_button_save(page)

    async def save(self) -> None:
        await self.save_button.click()
