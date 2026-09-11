from playwright.async_api import Locator, Page

# - native inputs/selects carry id="widget.cbid.<prefix>.<section>.<option>"
# - checkboxes carry a generated id and reference the widget id via the
#   data-widget-id attribute instead
# - div-based dropdowns (comboboxes) carry id="cbid.<prefix>.<section>.<option>"


def cbi_input(page: Page, section: str, option: str) -> Locator:
    return page.locator(f'input[id^="widget.cbid."][id$=".{section}.{option}"]')


def cbi_checkbox(page: Page, section: str, option: str) -> Locator:
    return page.locator(
        f'input[type="checkbox"][data-widget-id$=".{section}.{option}"]'
    )


def cbi_select(page: Page, section: str, option: str) -> Locator:
    return page.locator(f'select[id^="widget.cbid."][id$=".{section}.{option}"]')


def cbi_dropdown(page: Page, section: str, option: str) -> Locator:
    return page.locator(f'div.cbi-dropdown[id^="cbid."][id$=".{section}.{option}"]')


def cbi_dropdown_item(page: Page, section: str, option: str, value: str) -> Locator:
    return cbi_dropdown(page, section, option).locator(
        f'ul.dropdown li[data-value="{value}"]'
    )


def cbi_dropdown_selected(page: Page, section: str, option: str) -> Locator:
    return cbi_dropdown(page, section, option).locator("li[selected]")


def cbi_dropdown_input(page: Page, section: str, option: str) -> Locator:
    return cbi_dropdown(page, section, option).locator(
        "ul.dropdown input.create-item-input"
    )


def cbi_option_row(page: Page, widget: Locator) -> Locator:
    return page.locator("div.cbi-value").filter(has=widget)


def cbi_value_field(page: Page, label: str) -> Locator:
    return page.locator(
        f'div.cbi-value:has(label.cbi-value-title:text-is("{label}"))'
        " > div.cbi-value-field"
    )


def cbi_button(page: Page, label: str) -> Locator:
    return page.get_by_role("button", name=label, exact=True)


def cbi_page_action_apply(page: Page) -> Locator:
    # a LuCI ComboButton (div with a 'Save & Apply' entry), not a <button>
    return page.locator("div.cbi-page-actions .cbi-button-apply")


def luci_notification(page: Page, title: str) -> Locator:
    return page.locator(f'div.alert-message:has-text("{title}")')
