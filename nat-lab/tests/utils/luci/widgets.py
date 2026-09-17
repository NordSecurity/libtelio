from playwright.async_api import Locator, Page

# LuCI widget IDs follow the shape widget.cbid.<prefix>.<section>.<option>.
# We anchor the stable parts: the `widget.cbid.` prefix marks the element
# as a LuCI CBI widget, and the trailing .<section>.<option> identifies the field.


def cbi_input(page: Page, section: str, option: str) -> Locator:
    return page.locator(f'input[id^="widget.cbid."][id$=".{section}.{option}"]')


def cbi_button_save(page: Page) -> Locator:
    return page.locator("button.cbi-button-save").first
