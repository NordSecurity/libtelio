import pytest_asyncio
from tests.utils.playwright_browser import remote_page, save_failure_screenshot


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
