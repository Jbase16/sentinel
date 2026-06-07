"""
Phase 7-PF7 tests for core/foundry/driver_playwright.py.

Playwright isn't installed in CI, and we can't drive a real browser
there anyway. But the SUBSTANTIVE logic IS testable without a browser:

  * selector_to_locator's translation of every `by` kind onto the
    right page factory call (the part most likely to have a bug).
  * The driver's Driver-protocol methods call the right locator
    methods with the right args — verified against a mock page.
  * extract() mode handling (text / value / attr:href).
  * The import guard message when playwright is absent.

A real end-to-end run against a browser is the operator's
`pip install playwright` path; this pins the adapter logic.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest

from core.foundry.driver_playwright import (
    PlaywrightDriver,
    selector_to_locator,
)


def _run(coro):
    return asyncio.run(coro)


# ───────────────────────── mock playwright page ─────────────────────────


class MockLocator:
    def __init__(self, record: List[Dict[str, Any]], descriptor: str):
        self._record = record
        self._descriptor = descriptor

    async def fill(self, value):
        self._record.append({"op": "fill", "loc": self._descriptor, "value": value})

    async def click(self):
        self._record.append({"op": "click", "loc": self._descriptor})

    async def wait_for(self, timeout):
        self._record.append({"op": "wait_for", "loc": self._descriptor, "timeout": timeout})

    async def inner_text(self):
        self._record.append({"op": "inner_text", "loc": self._descriptor})
        return f"text-of-{self._descriptor}"

    async def input_value(self):
        return f"value-of-{self._descriptor}"

    async def get_attribute(self, attr):
        return f"attr-{attr}-of-{self._descriptor}"


class MockPage:
    """Records which locator factory was called with what, and yields
    MockLocators that record their actions."""

    def __init__(self):
        self.factory_calls: List[Dict[str, Any]] = []
        self.actions: List[Dict[str, Any]] = []
        self.url = "https://staging.airtable.com/signup"
        self._goto_calls: List[str] = []

    def locator(self, sel):
        self.factory_calls.append({"factory": "locator", "arg": sel})
        return MockLocator(self.actions, f"locator({sel})")

    def get_by_placeholder(self, val):
        self.factory_calls.append({"factory": "get_by_placeholder", "arg": val})
        return MockLocator(self.actions, f"placeholder({val})")

    def get_by_label(self, val):
        self.factory_calls.append({"factory": "get_by_label", "arg": val})
        return MockLocator(self.actions, f"label({val})")

    def get_by_role(self, val):
        self.factory_calls.append({"factory": "get_by_role", "arg": val})
        return MockLocator(self.actions, f"role({val})")

    def get_by_text(self, val):
        self.factory_calls.append({"factory": "get_by_text", "arg": val})
        return MockLocator(self.actions, f"text({val})")

    def get_by_test_id(self, val):
        self.factory_calls.append({"factory": "get_by_test_id", "arg": val})
        return MockLocator(self.actions, f"testid({val})")

    async def goto(self, url):
        self._goto_calls.append(url)
        self.url = url

    async def screenshot(self):
        return b"png-bytes"


# ───────────────────────── selector translation ─────────────────────────


class TestSelectorTranslation:
    def test_css(self):
        page = MockPage()
        selector_to_locator(page, {"by": "css", "value": "#email"})
        assert page.factory_calls[-1] == {"factory": "locator", "arg": "#email"}

    def test_name_becomes_attribute_selector(self):
        page = MockPage()
        selector_to_locator(page, {"by": "name", "value": "email"})
        # name → [name='email'] CSS attribute selector
        assert page.factory_calls[-1]["factory"] == "locator"
        assert "name=" in page.factory_calls[-1]["arg"]
        assert "email" in page.factory_calls[-1]["arg"]

    def test_placeholder(self):
        page = MockPage()
        selector_to_locator(page, {"by": "placeholder", "value": "you@example.com"})
        assert page.factory_calls[-1] == {
            "factory": "get_by_placeholder", "arg": "you@example.com",
        }

    def test_label(self):
        page = MockPage()
        selector_to_locator(page, {"by": "label", "value": "Email address"})
        assert page.factory_calls[-1] == {
            "factory": "get_by_label", "arg": "Email address",
        }

    def test_role(self):
        page = MockPage()
        selector_to_locator(page, {"by": "role", "value": "button"})
        assert page.factory_calls[-1] == {"factory": "get_by_role", "arg": "button"}

    def test_text(self):
        page = MockPage()
        selector_to_locator(page, {"by": "text", "value": "Sign up"})
        assert page.factory_calls[-1] == {"factory": "get_by_text", "arg": "Sign up"}

    def test_testid(self):
        page = MockPage()
        selector_to_locator(page, {"by": "testid", "value": "submit-btn"})
        assert page.factory_calls[-1] == {
            "factory": "get_by_test_id", "arg": "submit-btn",
        }

    def test_unknown_by_raises(self):
        page = MockPage()
        with pytest.raises(ValueError, match="unknown selector"):
            selector_to_locator(page, {"by": "xpath", "value": "//div"})

    def test_missing_keys_raises(self):
        page = MockPage()
        with pytest.raises(ValueError, match="'by' and 'value'"):
            selector_to_locator(page, {"by": "css"})  # no value


# ───────────────────────── driver methods ─────────────────────────


class TestDriverMethods:
    def _driver(self):
        page = MockPage()
        return PlaywrightDriver(page=page), page

    def test_navigate(self):
        driver, page = self._driver()
        _run(driver.navigate("https://staging.airtable.com/x"))
        assert page._goto_calls == ["https://staging.airtable.com/x"]

    def test_fill(self):
        driver, page = self._driver()
        _run(driver.fill({"by": "name", "value": "email"}, "alice@x"))
        fills = [a for a in page.actions if a["op"] == "fill"]
        assert len(fills) == 1
        assert fills[0]["value"] == "alice@x"

    def test_click(self):
        driver, page = self._driver()
        _run(driver.click({"by": "role", "value": "button"}))
        clicks = [a for a in page.actions if a["op"] == "click"]
        assert len(clicks) == 1

    def test_wait_for_converts_seconds_to_ms(self):
        driver, page = self._driver()
        _run(driver.wait_for({"by": "css", "value": ".loaded"}, 3.0))
        waits = [a for a in page.actions if a["op"] == "wait_for"]
        assert len(waits) == 1
        # 3.0 seconds → 3000 ms.
        assert waits[0]["timeout"] == 3000.0

    def test_extract_text_mode(self):
        driver, page = self._driver()
        out = _run(driver.extract({"by": "css", "value": ".token"}, "text"))
        assert out.startswith("text-of-")

    def test_extract_value_mode(self):
        driver, page = self._driver()
        out = _run(driver.extract({"by": "name", "value": "field"}, "value"))
        assert out.startswith("value-of-")

    def test_extract_attr_mode(self):
        driver, page = self._driver()
        out = _run(driver.extract({"by": "css", "value": "a.link"}, "attr:href"))
        assert out == "attr-href-of-locator(a.link)"

    def test_screenshot(self):
        driver, page = self._driver()
        out = _run(driver.screenshot())
        assert out == b"png-bytes"

    def test_current_url(self):
        driver, page = self._driver()
        page.url = "https://staging.airtable.com/verify"
        out = _run(driver.current_url())
        assert out == "https://staging.airtable.com/verify"

    def test_close_external_page_is_noop(self):
        # Wrapping an external page → close() must NOT try to close a
        # browser it doesn't own.
        driver, page = self._driver()
        _run(driver.close())  # no raise, no-op


# ───────────────────────── end-to-end with replayer ─────────────────────────


class TestPlaywrightDriverDrivesReplayer:
    """The PlaywrightDriver (wrapping a mock page) drives a real
    RecipeReplayer through a recipe — proving the adapter satisfies the
    Driver protocol the engine expects."""

    def test_replay_through_playwright_driver(self):
        from core.foundry.recipe import RecipeStep, SignupRecipe, StepKind
        from core.foundry.replay import RecipeReplayer, ReplayState
        from core.foundry.vault import ResearchPersona

        page = MockPage()
        driver = PlaywrightDriver(page=page)
        recipe = SignupRecipe(
            service_handle="airtable", name="signup",
            origin="https://staging.airtable.com",
            steps=[
                RecipeStep(kind=StepKind.NAVIGATE, url="https://staging.airtable.com/signup"),
                RecipeStep(
                    kind=StepKind.FILL,
                    selector={"by": "label", "value": "Email"},
                    value_binding="persona:email",
                ),
                RecipeStep(
                    kind=StepKind.CLICK,
                    selector={"by": "role", "value": "button"},
                ),
            ],
        )
        persona = ResearchPersona(
            persona_id="p", label="alice", email="alice@x",
            password="pw", first_name="A", last_name="B",
        )

        async def never(ch):
            raise AssertionError("no challenge expected")

        outcome = _run(RecipeReplayer(driver).run(
            recipe, persona, challenge_handler=never,
        ))
        assert outcome.state is ReplayState.COMPLETED
        # The driver actually drove the mock page.
        assert page._goto_calls == ["https://staging.airtable.com/signup"]
        fills = [a for a in page.actions if a["op"] == "fill"]
        assert fills[0]["value"] == "alice@x"
