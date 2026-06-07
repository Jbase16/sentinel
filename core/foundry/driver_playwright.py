"""
core/foundry/driver_playwright.py — Phase 7-PF7: the real browser Driver.

Maps the Foundry's Driver protocol (PF3) onto Playwright's async API,
so the RecipeReplayer can drive an actual browser through a signup.

Import-guarded: this module loads even when playwright isn't installed
(so the rest of the Foundry imports cleanly). PlaywrightDriver only
fails — with a clear, actionable message — when you try to construct
one without the dependency. The operator activates real browser
automation with:

    pip install playwright
    playwright install chromium

Why Playwright over the Chrome MCP / computer-use: the backend Python
process needs to drive the browser ITSELF (the replay runs server-
side). MCP tools are available to the agent, not the running server.
Playwright gives the server a first-class async browser it owns.

The selector translation is the substantive, testable logic — it maps
the recipe's driver-agnostic selector spec
    {"by": "css"|"name"|"label"|"placeholder"|"role"|"text", "value": ...}
onto Playwright locators. That mapping is unit-tested against a mock
page (no real browser needed in CI).

Headful vs headless: account signup frequently trips bot-detection in
headless mode. The driver defaults to HEADFUL (a visible browser
window) — which also makes the human handoff natural: when a CAPTCHA
appears, the human is looking at the same real browser window the
automation is driving, and solves it right there. Headless is
available for environments without a display.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _require_playwright():
    """Import playwright.async_api or raise a clear, actionable error."""
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        return async_playwright
    except ImportError as e:
        raise RuntimeError(
            "PlaywrightDriver needs the 'playwright' package, which is not "
            "installed. Activate real browser automation with:\n"
            "    pip install playwright\n"
            "    playwright install chromium\n"
            f"(underlying import error: {e})"
        ) from e


def selector_to_locator(page, selector: Dict[str, str]):
    """Translate a recipe selector spec into a Playwright locator.

    Pure-ish (only touches `page`'s locator factories, no I/O) so it's
    unit-testable with a mock page. Supported `by` values:

        css         → page.locator(value)
        name        → page.locator("[name='value']")
        placeholder → page.get_by_placeholder(value)
        label       → page.get_by_label(value)
        role        → page.get_by_role(value)
        text        → page.get_by_text(value)
        testid      → page.get_by_test_id(value)

    Raises ValueError for an unknown `by` or a missing value.
    """
    if not selector or "by" not in selector or "value" not in selector:
        raise ValueError(
            f"selector must have 'by' and 'value' keys, got {selector!r}"
        )
    by = selector["by"]
    value = selector["value"]
    if by == "css":
        return page.locator(value)
    if by == "name":
        # CSS attribute selector — robust + driver-agnostic.
        return page.locator(f"[name={value!r}]")
    if by == "placeholder":
        return page.get_by_placeholder(value)
    if by == "label":
        return page.get_by_label(value)
    if by == "role":
        return page.get_by_role(value)
    if by == "text":
        return page.get_by_text(value)
    if by == "testid":
        return page.get_by_test_id(value)
    raise ValueError(
        f"unknown selector 'by'={by!r} — supported: css, name, "
        f"placeholder, label, role, text, testid"
    )


class PlaywrightDriver:
    """A Driver (PF3 protocol) backed by a Playwright page.

    Two construction paths:
      * `await PlaywrightDriver.launch(headless=False)` — owns the
        whole browser lifecycle (launches chromium, opens a page).
      * `PlaywrightDriver(page=existing_page)` — wraps a page the
        caller already has (e.g. an existing authenticated session,
        or for tests, a mock page).

    Always `await driver.close()` when done with a launched driver to
    release the browser. Wrapping an external page does NOT close it.
    """

    def __init__(self, page=None, *, _owns_browser=False, _pw=None, _browser=None):
        self._page = page
        self._owns_browser = _owns_browser
        self._pw = _pw
        self._browser = _browser

    @classmethod
    async def launch(
        cls, *, headless: bool = False, default_timeout_ms: int = 15000,
        user_agent: Optional[str] = None,
    ) -> "PlaywrightDriver":
        """Launch a chromium browser + page and return a driver that
        owns them. Defaults to HEADFUL so the human shares the browser
        window the automation drives (natural CAPTCHA handoff)."""
        async_playwright = _require_playwright()
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=headless)
        context_kwargs: Dict[str, Any] = {}
        if user_agent:
            context_kwargs["user_agent"] = user_agent
        context = await browser.new_context(**context_kwargs)
        page = await context.new_page()
        page.set_default_timeout(default_timeout_ms)
        logger.info(
            "[playwright-driver] launched chromium (headless=%s)", headless,
        )
        return cls(page=page, _owns_browser=True, _pw=pw, _browser=browser)

    # ── Driver protocol ──

    async def navigate(self, url: str) -> None:
        await self._page.goto(url)

    async def fill(self, selector: Dict[str, str], value: str) -> None:
        locator = selector_to_locator(self._page, selector)
        await locator.fill(value)

    async def click(self, selector: Dict[str, str]) -> None:
        locator = selector_to_locator(self._page, selector)
        await locator.click()

    async def wait_for(self, selector: Dict[str, str], timeout_s: float) -> None:
        locator = selector_to_locator(self._page, selector)
        await locator.wait_for(timeout=timeout_s * 1000.0)

    async def extract(self, selector: Dict[str, str], mode: str) -> str:
        locator = selector_to_locator(self._page, selector)
        if mode == "text":
            return await locator.inner_text()
        if mode == "value":
            return await locator.input_value()
        if mode.startswith("attr:"):
            attr = mode.split(":", 1)[1]
            val = await locator.get_attribute(attr)
            return val or ""
        # Fallback: text content.
        return await locator.inner_text()

    async def screenshot(self) -> bytes:
        try:
            return await self._page.screenshot()
        except Exception as e:
            logger.warning("[playwright-driver] screenshot failed: %s", e)
            return b""

    async def current_url(self) -> str:
        return self._page.url

    # ── lifecycle ──

    async def close(self) -> None:
        """Release the browser if this driver launched it. Wrapping an
        external page is a no-op."""
        if not self._owns_browser:
            return
        try:
            if self._browser is not None:
                await self._browser.close()
            if self._pw is not None:
                await self._pw.stop()
        except Exception as e:
            logger.warning("[playwright-driver] close failed: %s", e)
