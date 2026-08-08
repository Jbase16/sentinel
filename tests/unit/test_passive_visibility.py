import pytest

from core.behavior.passive_visibility import (
    AnonymousPassiveVisibilityBoundary,
    PASSIVE_VISIBILITY_WORKFLOW,
    PassiveHTTPResponse,
    PassiveVisibilityConfig,
    PassiveVisibilityDenied,
)
from core.foundry.authorization import AuthorizationEnvelope


def _envelope(*, workflows=None):
    envelope = AuthorizationEnvelope(
        envelope_id="a" * 32,
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=["https://example.test"],
        authorization_basis="owned acceptance target",
        disclosure_attestation=True,
        allowed_workflows=list(workflows or [PASSIVE_VISIBILITY_WORKFLOW]),
    )
    envelope.sign()
    return envelope


@pytest.mark.asyncio
async def test_anonymous_passive_visibility_is_bounded_and_never_claims_proof():
    requested = []
    responses = {
        "https://example.test/": PassiveHTTPResponse(
            200,
            {"content-type": "text/html"},
            """
            <html><head><title>Home</title></head><body>
              <a href="/p/public-note#content">Shared preview</a>
              <a href="https://outside.test/escape">Outside</a>
              <a href="/p/public-note">Duplicate</a>
            </body></html>
            """,
        ),
        "https://example.test/p/public-note": PassiveHTTPResponse(
            200,
            {"content-type": "text/html; charset=utf-8"},
            "<html><head><title>Public note</title></head>"
            "<body><article>Visible content</article></body></html>",
        ),
    }

    async def fetch(url):
        requested.append(url)
        return responses[url]

    result = await AnonymousPassiveVisibilityBoundary(
        target_url="https://example.test/",
        authorization=_envelope(),
        fetch=fetch,
    ).observe()

    assert requested == [
        "https://example.test/",
        "https://example.test/p/public-note",
    ]
    assert result["finding_authority"] is False
    assert result["finding_confirmed"] is False
    assert result["execution"] == {
        "status": "completed",
        "requests_attempted": 2,
        "requests_sent": 2,
        "mutations": 0,
        "authenticated_sessions": 0,
    }
    assert result["adaptive_execution"]["status"] == "skipped"
    assert result["independent_proof"]["status"] == "skipped"
    assert result["orchestration_receipt"] is None
    pages = result["observation"]["discovered_public_pages"]
    assert pages[0]["title"] == "Public note"
    assert pages[0]["article_count"] == 1
    assert "Visible content" not in str(result)


@pytest.mark.asyncio
async def test_anonymous_passive_visibility_refuses_before_traffic_without_workflow():
    called = False

    async def fetch(_url):
        nonlocal called
        called = True
        raise AssertionError("authorization must precede traffic")

    with pytest.raises(PassiveVisibilityDenied, match="authorization_denied"):
        AnonymousPassiveVisibilityBoundary(
            target_url="https://example.test/",
            authorization=_envelope(workflows=["different_workflow"]),
            fetch=fetch,
        )

    assert called is False


@pytest.mark.asyncio
async def test_anonymous_passive_visibility_honors_the_request_budget():
    requested = []

    async def fetch(url):
        requested.append(url)
        if url == "https://example.test/":
            return PassiveHTTPResponse(
                200,
                {"content-type": "text/html"},
                '<a href="/one">One</a><a href="/two">Two</a><a href="/three">Three</a>',
            )
        return PassiveHTTPResponse(200, {"content-type": "text/html"}, "<p>public</p>")

    result = await AnonymousPassiveVisibilityBoundary(
        target_url="https://example.test/",
        authorization=_envelope(),
        fetch=fetch,
        config=PassiveVisibilityConfig(max_total_requests=3, max_discovered_links=2),
    ).observe()

    assert requested == [
        "https://example.test/",
        "https://example.test/one",
        "https://example.test/two",
    ]
    assert result["execution"]["requests_sent"] == 3
