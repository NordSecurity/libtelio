import os
import pytest
from contextlib import asynccontextmanager
from playwright.async_api import Browser, BrowserContext, Page, async_playwright
from tests.config import LAN_ADDR_MAP
from tests.utils.connection import ConnectionTag
from tests.utils.logger import log
from tests.utils.testing import get_current_test_log_path
from typing import AsyncIterator

PLAYWRIGHT_RUNNER_HOST = LAN_ADDR_MAP[ConnectionTag.DOCKER_PLAYWRIGHT_RUNNER_1][
    "primary"
]
PLAYWRIGHT_RUNNER_PORT = 4444
PLAYWRIGHT_RUNNER_WS_PATH = "playwright"
PLAYWRIGHT_RUNNER_WS = f"ws://{PLAYWRIGHT_RUNNER_HOST}:{PLAYWRIGHT_RUNNER_PORT}/{PLAYWRIGHT_RUNNER_WS_PATH}"


@asynccontextmanager
async def remote_browser() -> AsyncIterator[Browser]:
    async with async_playwright() as p:
        browser = await p.chromium.connect(PLAYWRIGHT_RUNNER_WS)
        try:
            yield browser
        finally:
            await browser.close()


@asynccontextmanager
async def remote_page() -> AsyncIterator[Page]:
    async with remote_browser() as browser:
        context: BrowserContext = await browser.new_context(ignore_https_errors=True)
        try:
            page = await context.new_page()
            yield page
        finally:
            await context.close()


async def save_failure_screenshot(
    page: Page,
    request: pytest.FixtureRequest,
    name: str | None = None,
) -> None:
    failed = False
    for phase in ("setup", "call"):
        rep = getattr(request.node, f"rep_{phase}", None)
        if rep is not None and rep.failed:
            failed = True
            break
    if not failed:
        return
    log_dir = get_current_test_log_path()
    filename = name if name is not None else f"{os.path.basename(log_dir)}.png"
    os.makedirs(log_dir, exist_ok=True)
    try:
        await page.screenshot(path=os.path.join(log_dir, filename), full_page=True)
    except Exception as e:
        log.warning("Failed to save failure screenshot: %r", e)
