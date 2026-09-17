from playwright.async_api import Page
from tests.config import LAN_ADDR_MAP
from tests.utils.connection import ConnectionTag

LUCI_PATH = "/cgi-bin/luci"
DEFAULT_USER = "root"
DEFAULT_PASSWORD = ""


def luci_base_url(tag: ConnectionTag) -> str:
    ip = LAN_ADDR_MAP[tag]["primary"]
    return f"http://{ip}{LUCI_PATH}"


class LuciPage:
    URL: str = ""

    def __init__(self, page: Page, base_url: str):
        self.page = page
        self.base_url = base_url

    async def login(
        self, user: str = DEFAULT_USER, password: str = DEFAULT_PASSWORD
    ) -> None:
        await self.page.goto(self.base_url)
        username = self.page.locator('input[name="luci_username"]')
        if await username.count() == 0:
            return
        await username.fill(user)
        password_field = self.page.locator('input[name="luci_password"]')
        await password_field.fill(password)
        await password_field.press("Enter")
        await self.page.locator("a.menu").first.wait_for(state="visible")

    async def open(self) -> None:
        await self.page.goto(self.base_url + self.URL)
        await self.wait_loaded()

    async def wait_loaded(self) -> None:
        await self.page.locator(".cbi-map").first.wait_for(state="visible")

    async def click_menu_item(self, top_menu: str, item_label: str) -> None:
        await self.page.locator(f'li.dropdown > a.menu:has-text("{top_menu}")').hover()
        await self.page.get_by_role("link", name=item_label, exact=True).click()
        await self.wait_loaded()
