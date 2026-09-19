"""OCB-S19 artifact sanitization, including reflected and restart secrets.

All credentials below are synthetic fixture sentinels, never operator values.
"""

from dataclasses import asdict
import json
import pickle
from urllib.parse import quote

import pytest

from core.ghost.flow import FlowStep
from core.verify.console import create_session_from_target
from core.verify.promoter import ArtifactSanitizer, promote_transcript_to_repro, render_curl


def _captured_step():
    token = "fixture-bearer-39dd157a"
    cookie = "fixture-cookie-784d23b6"
    custom = "fixture-persona-602be1da"
    issued = "fixture-issued-884bea11"
    step = FlowStep(
        "POST",
        f"https://fixture.example/{token}/records?session={cookie}&record=7",
        headers={
            "Authorization": f"Bearer {token}",
            "Cookie": f"sid={cookie}",
            "X-Unusual-Principal": custom,
            "Content-Type": "application/json",
        },
        request_body=json.dumps({"owner": custom, token: {"name": "visible", "count": 7}}),
    )
    step.set_response(
        status=200,
        headers={"Set-Cookie": f"auth={issued}; Secure; HttpOnly"},
        body=json.dumps({"echo": [token, cookie, custom, issued], issued: "retained"}),
        cookies_after_step={"sid": cookie},
    )
    return step, (token, cookie, custom, issued)


def _assert_absent(value, secrets):
    rendered = json.dumps(value, sort_keys=True)
    for secret in secrets:
        assert secret not in rendered


def test_capture_secrets_are_removed_from_every_promoted_field_and_raw_capture_survives():
    step, secrets = _captured_step()
    session = create_session_from_target("https://fixture.example/")
    session.append_exchange(step)
    original_body = step.request_body

    entries, legend = promote_transcript_to_repro(session)

    _assert_absent([asdict(item) for item in entries], secrets)
    _assert_absent([item.markdown for item in entries], secrets)
    _assert_absent(legend, secrets)
    assert "$TOKEN" in entries[0].curl
    assert "$SESSION_ID" in entries[0].curl
    assert '"count": 7' in entries[0].curl
    assert '"name": "visible"' in entries[0].curl
    assert "record=$VALUE" in entries[0].url
    assert step.request_body == original_body
    assert secrets[0] in step.headers["authorization"]


def test_full_transcript_and_persona_values_sanitize_selected_reflections():
    step, secrets = _captured_step()
    persona = "fixture-extra-persona-5d2db578"
    session = create_session_from_target("https://fixture.example/")
    session.persona_headers = {"X-Custom": persona}
    session.append_exchange(step)
    reflection = FlowStep("GET", f"https://fixture.example/{persona}")
    reflection.persona_at_capture = persona
    reflection.set_response(status=200, body=f"{' '.join(secrets)} {persona}")
    session.append_exchange(reflection)

    entries, _ = promote_transcript_to_repro(session, exchange_indices=[1])

    _assert_absent([asdict(item) for item in entries], (*secrets, persona))
    assert len(entries) == 1


def test_hash_only_restart_sanitizes_keys_values_and_encoded_reflections():
    step, secrets = _captured_step()
    encoded_secret = "fixture / unicode-\u00e9-6e730d94"
    live = ArtifactSanitizer((step,), sensitive_values=(encoded_secret,))
    fingerprints = json.loads(json.dumps(live.fingerprints()))
    _assert_absent(fingerprints, (*secrets, encoded_secret))
    _assert_absent(repr(live), (*secrets, encoded_secret))
    restarted = ArtifactSanitizer(secret_fingerprints=fingerprints)
    content = {secrets[0]: [*secrets, quote(encoded_secret, safe=""), encoded_secret]}

    assert restarted.contains_secret(content)
    cleaned = restarted.value(content)

    _assert_absent(cleaned, (*secrets, encoded_secret))
    assert not restarted.contains_secret(cleaned)
    assert cleaned == live.value(content)
    assert restarted.fingerprints() == live.fingerprints()


def test_overlapping_and_adjacent_secrets_have_identical_redaction_after_restart():
    live = ArtifactSanitizer(sensitive_values=("fixture-overlap-one", "overlap-one-two"))
    restarted = ArtifactSanitizer(secret_fingerprints=live.fingerprints())
    content = "fixture-overlap-one-two / fixture-overlap-onefixture-overlap-one"
    assert live.text(content) == restarted.text(content)
    assert live.text(content) == "$REDACTED / $REDACTED$REDACTED"


def test_protected_response_values_redact_reflected_claims_after_restart():
    private_value = "fixture-protected-response-84e5183d"
    step = FlowStep("GET", "https://fixture.example/")
    step.set_response(status=200, body=json.dumps({"privateNote": [private_value]}))
    legacy = ArtifactSanitizer((step,))
    assert legacy.text(private_value) == private_value
    live = ArtifactSanitizer((step,), redact_response_values=True)
    restarted = ArtifactSanitizer(secret_fingerprints=live.fingerprints())
    assert restarted.text(f"Evidence exposed {private_value}.") == "Evidence exposed $REDACTED."
    assert not restarted.contains_secret(restarted.value({"title": private_value}))


@pytest.mark.parametrize("content", [
    '{"password":"fixture-password-390a","nested":{"access_token":"fixture-access-713b"}}',
    "token=fixture-access-713b&password=fixture-password-390a",
    "Authorization: Bearer fixture-access-713b\nCookie: sid=fixture-password-390a",
])
def test_unseen_named_credentials_are_redacted_without_a_capture(content):
    sanitizer = ArtifactSanitizer()
    cleaned = sanitizer.body(content)
    assert "fixture-password-390a" not in cleaned
    assert "fixture-access-713b" not in cleaned


def test_nonstandard_headers_and_spoofed_media_values_are_not_exempt():
    secret = "fixture-content-type-2a470c7b"
    step = FlowStep("GET", "https://fixture.example/", headers={
        "Content-Type": secret,
        "Accept": "application/json, text/plain; q=0.5",
        "User-Agent": "fixture-agent-07e6d651",
        "X-Private": "fixture-custom-51bcebcf",
    })
    step.set_response(status=200, body=secret)

    sanitizer = ArtifactSanitizer((step,))
    headers, _ = sanitizer.headers(step.headers)
    assert headers["content-type"] == "$REDACTED"
    assert headers["accept"] == "application/json, text/plain; q=0.5"
    assert headers["user-agent"] == "$REDACTED"
    assert headers["x-private"] == "$REDACTED"
    assert sanitizer.body(secret) == "$REDACTED"


def test_secret_disguised_as_a_media_subtype_is_redacted():
    secret = "application/fixture-private-token-99fb386d"
    step = FlowStep("GET", "https://fixture.example/", headers={"Content-Type": secret})
    sanitizer = ArtifactSanitizer((step,))
    assert sanitizer.headers(step.headers)[0]["content-type"] == "$REDACTED"
    assert sanitizer.text(secret) == "$REDACTED"


def test_raw_credential_container_refuses_pickle_serialization():
    secret = "fixture-never-persist-c70e69cd"
    sanitizer = ArtifactSanitizer(sensitive_values=(secret,))
    with pytest.raises(TypeError) as caught:
        pickle.dumps(sanitizer)
    assert secret not in str(caught.value)


def test_unknown_header_structured_credential_is_redacted_when_reflected():
    secret = "fixture-structured-8ab39599"
    step = FlowStep("GET", "https://fixture.example/", headers={"X-Private": f"token={secret}"})
    sanitizer = ArtifactSanitizer((step,))
    assert sanitizer.text(secret) == "$REDACTED"


def test_url_credentials_refuse_without_serializing_the_value():
    secret = "fixture-password-f7c42cb8"
    step = FlowStep("GET", f"https://operator:{secret}@fixture.example/")
    with pytest.raises(ValueError) as caught:
        render_curl(step)
    assert secret not in str(caught.value)
    assert "credentials" in str(caught.value)


def test_reflected_key_collision_refuses_without_leaking_the_keys():
    secrets = ("fixture-first-cc8c4bc6", "fixture-second-adb75625")
    sanitizer = ArtifactSanitizer(sensitive_values=secrets)
    with pytest.raises(ValueError) as caught:
        sanitizer.value({secrets[0]: 1, secrets[1]: 2})
    _assert_absent(str(caught.value), secrets)
    assert "collide" in str(caught.value)


def test_leak_check_detects_sanitizer_bypass_and_clears_only_after_redaction():
    step, _ = _captured_step()
    sanitizer = ArtifactSanitizer((step,))
    raw, _ = render_curl(step, sanitize=False)
    safe, _ = render_curl(step)
    assert sanitizer.contains_secret(raw)
    assert not sanitizer.contains_secret(safe)


def test_credential_in_long_response_is_sanitized_before_excerpt_truncation():
    secret = "fixture-long-token-b5807897"
    step = FlowStep("GET", "https://fixture.example/", headers={"Authorization": f"Bearer {secret}"})
    step.set_response(status=200, body="x" * 390 + secret + "y" * 100)
    session = create_session_from_target("https://fixture.example/")
    session.append_exchange(step)
    entries, _ = promote_transcript_to_repro(session)
    assert secret[:10] not in entries[0].response_excerpt
    assert "…" in entries[0].response_excerpt
