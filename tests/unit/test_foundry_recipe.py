"""
Phase 7-PF1 tests for core/foundry/recipe.py.

The SignupRecipe is the Foundry's atomic unit — a parameterizable,
serializable signup-flow description. Tests pin:

  * resolve_binding for every BindingKind, including the deliberate
    refusal to resolve verification: bindings synchronously.
  * generated:password meets common password-policy classes.
  * RecipeStep.validate enforces per-kind required fields.
  * SignupRecipe.validate catches malformed steps with index context.
  * derive_required_persona_fields scans persona: bindings.
  * Full to_dict/from_dict round-trip (recipe + steps).
"""
from __future__ import annotations

import json

import pytest

from core.foundry.recipe import (
    BindingKind,
    ChallengeKind,
    RecipeStep,
    SignupRecipe,
    StepKind,
    _default_generator,
    resolve_binding,
)


# ───────────────────────── resolve_binding ─────────────────────────


class TestResolveBinding:
    def test_literal(self):
        assert resolve_binding("literal:hello world") == "hello world"

    def test_literal_with_colon_in_value(self):
        # The value can itself contain colons — only the FIRST colon
        # splits kind from arg.
        assert resolve_binding("literal:https://example.com") == "https://example.com"

    def test_persona_field(self):
        out = resolve_binding("persona:email", persona={"email": "a@b.com"})
        assert out == "a@b.com"

    def test_persona_missing_field_raises(self):
        with pytest.raises(ValueError, match="no field"):
            resolve_binding("persona:phone", persona={"email": "a@b.com"})

    def test_persona_no_persona_raises(self):
        with pytest.raises(ValueError):
            resolve_binding("persona:email", persona=None)

    def test_extracted_value(self):
        out = resolve_binding("extracted:csrf", extracted={"csrf": "tok123"})
        assert out == "tok123"

    def test_extracted_missing_raises(self):
        with pytest.raises(ValueError, match="no variable"):
            resolve_binding("extracted:csrf", extracted={})

    def test_generated_password_via_default(self):
        out = resolve_binding("generated:password")
        assert len(out) == 20

    def test_generated_with_custom_generator(self):
        out = resolve_binding(
            "generated:thing", generator=lambda kind: f"gen-{kind}"
        )
        assert out == "gen-thing"

    def test_verification_binding_refuses_sync_resolution(self):
        # verification: bindings require a runtime fetch — calling
        # resolve_binding on one must raise so misuse is loud.
        with pytest.raises(ValueError, match="cannot be resolved"):
            resolve_binding("verification:email_link")

    def test_unknown_kind_raises(self):
        with pytest.raises(ValueError, match="unknown binding kind"):
            resolve_binding("bogus:foo")

    def test_missing_colon_raises(self):
        with pytest.raises(ValueError, match="missing ':'"):
            resolve_binding("noColonHere")


class TestDefaultGenerator:
    def test_password_has_all_classes(self):
        for _ in range(20):  # generate a few — randomness
            pw = _default_generator("password")
            assert len(pw) == 20
            assert any(c.islower() for c in pw), f"no lowercase in {pw!r}"
            assert any(c.isupper() for c in pw), f"no uppercase in {pw!r}"
            assert any(c.isdigit() for c in pw), f"no digit in {pw!r}"
            assert any(c in "!@#$%^&*-_=+" for c in pw), f"no symbol in {pw!r}"

    def test_username_prefixed(self):
        u = _default_generator("username")
        assert u.startswith("sf_")

    def test_unknown_generated_kind_raises(self):
        with pytest.raises(ValueError):
            _default_generator("nonsense")


# ───────────────────────── RecipeStep.validate ─────────────────────────


class TestStepValidate:
    def test_navigate_requires_url(self):
        with pytest.raises(ValueError, match="requires a url"):
            RecipeStep(kind=StepKind.NAVIGATE).validate()
        # Valid one doesn't raise.
        RecipeStep(kind=StepKind.NAVIGATE, url="https://x").validate()

    def test_fill_requires_selector_and_binding(self):
        with pytest.raises(ValueError, match="requires a selector"):
            RecipeStep(kind=StepKind.FILL, value_binding="persona:email").validate()
        with pytest.raises(ValueError, match="requires a value_binding"):
            RecipeStep(
                kind=StepKind.FILL,
                selector={"by": "css", "value": "#email"},
            ).validate()
        # Valid.
        RecipeStep(
            kind=StepKind.FILL,
            selector={"by": "css", "value": "#email"},
            value_binding="persona:email",
        ).validate()

    def test_click_requires_selector(self):
        with pytest.raises(ValueError, match="requires a selector"):
            RecipeStep(kind=StepKind.CLICK).validate()

    def test_extract_requires_selector_and_extract_as(self):
        with pytest.raises(ValueError, match="requires a selector"):
            RecipeStep(kind=StepKind.EXTRACT, extract_as="token").validate()
        with pytest.raises(ValueError, match="requires extract_as"):
            RecipeStep(
                kind=StepKind.EXTRACT,
                selector={"by": "css", "value": ".token"},
            ).validate()

    def test_challenge_requires_kind(self):
        with pytest.raises(ValueError, match="requires a challenge_kind"):
            RecipeStep(kind=StepKind.CHALLENGE).validate()
        RecipeStep(
            kind=StepKind.CHALLENGE,
            challenge_kind=ChallengeKind.CAPTCHA,
        ).validate()


# ───────────────────────── SignupRecipe ─────────────────────────


def _valid_recipe() -> SignupRecipe:
    return SignupRecipe(
        service_handle="airtable",
        name="Airtable staging signup",
        origin="https://staging.airtable.com",
        steps=[
            RecipeStep(kind=StepKind.NAVIGATE, url="https://staging.airtable.com/signup"),
            RecipeStep(
                kind=StepKind.FILL, label="fill email",
                selector={"by": "name", "value": "email"},
                value_binding="persona:email",
            ),
            RecipeStep(
                kind=StepKind.FILL, label="fill password",
                selector={"by": "name", "value": "password"},
                value_binding="generated:password",
            ),
            RecipeStep(
                kind=StepKind.CLICK, label="submit",
                selector={"by": "css", "value": "button[type=submit]"},
            ),
            RecipeStep(
                kind=StepKind.CHALLENGE, label="email verification",
                challenge_kind=ChallengeKind.EMAIL_LINK,
                challenge_prompt="Click the verification link in the email.",
            ),
            RecipeStep(
                kind=StepKind.EXTRACT, label="grab API token",
                selector={"by": "css", "value": ".api-token"},
                extract_as="api_token",
            ),
        ],
    )


class TestSignupRecipe:
    def test_valid_recipe_passes(self):
        _valid_recipe().validate()  # no raise

    def test_empty_steps_raises(self):
        r = SignupRecipe(service_handle="x", name="x", origin="https://x", steps=[])
        with pytest.raises(ValueError, match="no steps"):
            r.validate()

    def test_malformed_step_reports_index(self):
        r = _valid_recipe()
        # Break step 2 (the password fill) — remove its binding.
        r.steps[2].value_binding = None
        with pytest.raises(ValueError, match="step 2"):
            r.validate()

    def test_derive_required_persona_fields(self):
        r = _valid_recipe()
        fields = r.derive_required_persona_fields()
        # Only the persona: binding (email) — generated:password is NOT
        # a persona field.
        assert fields == ["email"]
        assert r.required_persona_fields == ["email"]

    def test_challenge_steps_listed(self):
        r = _valid_recipe()
        challenges = r.challenge_steps()
        assert len(challenges) == 1
        assert challenges[0].challenge_kind is ChallengeKind.EMAIL_LINK

    def test_round_trip_via_dict(self):
        r = _valid_recipe()
        r.derive_required_persona_fields()
        restored = SignupRecipe.from_dict(r.to_dict())
        assert restored.service_handle == r.service_handle
        assert restored.origin == r.origin
        assert len(restored.steps) == len(r.steps)
        # Step fidelity.
        assert restored.steps[1].value_binding == "persona:email"
        assert restored.steps[4].challenge_kind is ChallengeKind.EMAIL_LINK
        assert restored.steps[5].extract_as == "api_token"
        assert restored.required_persona_fields == ["email"]

    def test_to_dict_is_json_safe(self):
        r = _valid_recipe()
        json.dumps(r.to_dict())  # must not raise
