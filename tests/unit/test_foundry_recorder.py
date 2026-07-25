"""
Phase 7-PF8 tests for core/foundry/recorder.py.

The recorder's value is binding inference — "look at the field, figure
out what it means". Tests pin the inference for every field kind and
the confirm-password consistency, plus the action-log → recipe translation
and the end-to-end "recorded recipe replays correctly".
"""
from __future__ import annotations

import asyncio

from core.foundry.recipe import ChallengeKind, StepKind
from core.foundry.recorder import (
    RecordedAction,
    infer_binding,
    record_to_recipe,
)


def _run(coro):
    return asyncio.run(coro)


# ───────────────────────── binding inference ─────────────────────────


class TestInferBinding:
    def test_email_by_type(self):
        assert infer_binding({"type": "email"}) == "persona:email"

    def test_email_by_autocomplete(self):
        assert infer_binding({"autocomplete": "email"}) == "persona:email"

    def test_email_by_name(self):
        assert infer_binding({"name": "user_email"}) == "persona:email"

    def test_email_by_placeholder(self):
        assert infer_binding({"placeholder": "you@example.com email"}) == "persona:email"

    def test_password_by_type(self):
        assert infer_binding({"type": "password"}) == "persona:password"

    def test_password_by_name(self):
        assert infer_binding({"name": "passwd"}) == "persona:password"

    def test_confirm_password_uses_persona_password(self):
        # Password and confirmation both resolve to the vault-backed password.
        assert infer_binding({"type": "password", "name": "confirm_password"}) == \
            "persona:password"

    def test_password_seen_compatibility_argument_preserves_persona_binding(self):
        # Existing callers may still supply password_seen; the binding stays stable.
        assert infer_binding({"type": "password"}, password_seen=True) == \
            "persona:password"

    def test_phone_by_autocomplete(self):
        assert infer_binding({"autocomplete": "tel"}) == "persona:phone"

    def test_phone_by_name(self):
        assert infer_binding({"name": "mobile_number"}) == "persona:phone"

    def test_first_name_by_autocomplete(self):
        assert infer_binding({"autocomplete": "given-name"}) == "persona:first_name"

    def test_first_name_by_label(self):
        assert infer_binding({"label": "First Name"}) == "persona:first_name"

    def test_last_name_by_autocomplete(self):
        assert infer_binding({"autocomplete": "family-name"}) == "persona:last_name"

    def test_last_name_by_name(self):
        assert infer_binding({"name": "surname"}) == "persona:last_name"

    def test_username_field(self):
        assert infer_binding({"name": "username"}) == "generated:username"

    def test_date_of_birth(self):
        assert infer_binding({"name": "date_of_birth"}) == "persona:date_of_birth"

    def test_unrecognized_field_flagged_for_review(self):
        binding = infer_binding({"name": "favorite_color"})
        assert binding == "literal:REVIEW_THIS_FIELD"

    def test_email_wins_over_generic_name(self):
        # A field named "email_name" should be email, not a name field.
        assert infer_binding({"name": "email_address"}) == "persona:email"


# ───────────────────────── action log → recipe ─────────────────────────


def _airtable_signup_actions():
    """A synthetic capture of an Airtable-shaped signup."""
    return [
        RecordedAction(action="navigate", url="https://staging.airtable.com/signup"),
        RecordedAction(
            action="fill", selector={"by": "name", "value": "email"},
            field={"name": "email", "type": "email", "autocomplete": "email"},
        ),
        RecordedAction(
            action="fill", selector={"by": "name", "value": "firstName"},
            field={"name": "firstName", "autocomplete": "given-name"},
        ),
        RecordedAction(
            action="fill", selector={"by": "name", "value": "password"},
            field={"name": "password", "type": "password"},
        ),
        RecordedAction(
            action="fill", selector={"by": "name", "value": "confirmPassword"},
            field={"name": "confirmPassword", "type": "password"},
        ),
        RecordedAction(
            action="click", selector={"by": "role", "value": "button"},
            label="submit",
        ),
        RecordedAction(action="challenge", challenge_kind="recaptcha"),
        RecordedAction(action="challenge", challenge_kind="email_link"),
    ]


class TestRecordToRecipe:
    def test_produces_valid_recipe(self):
        recipe = record_to_recipe(
            service_handle="airtable", origin="https://staging.airtable.com",
            name="Airtable signup", actions=_airtable_signup_actions(),
        )
        recipe.validate()  # no raise
        assert recipe.service_handle == "airtable"
        assert len(recipe.steps) == 8

    def test_bindings_inferred_correctly(self):
        recipe = record_to_recipe(
            service_handle="airtable", origin="https://staging.airtable.com",
            name="signup", actions=_airtable_signup_actions(),
        )
        fills = [s for s in recipe.steps if s.kind is StepKind.FILL]
        bindings = [f.value_binding for f in fills]
        assert bindings == [
            "persona:email",
            "persona:first_name",
            "persona:password",
            "persona:password",  # confirmation reuses the persona password
        ]

    def test_required_persona_fields_derived(self):
        recipe = record_to_recipe(
            service_handle="airtable", origin="https://staging.airtable.com",
            name="signup", actions=_airtable_signup_actions(),
        )
        # email + first_name + password
        assert set(recipe.required_persona_fields) == {"email", "first_name", "password"}

    def test_challenges_recorded(self):
        recipe = record_to_recipe(
            service_handle="airtable", origin="https://staging.airtable.com",
            name="signup", actions=_airtable_signup_actions(),
        )
        challenges = recipe.challenge_steps()
        kinds = {c.challenge_kind for c in challenges}
        assert ChallengeKind.CAPTCHA in kinds
        assert ChallengeKind.EMAIL_LINK in kinds

    def test_unrecognized_field_noted(self):
        actions = [
            RecordedAction(action="navigate", url="https://staging.airtable.com/s"),
            RecordedAction(
                action="fill", selector={"by": "name", "value": "color"},
                field={"name": "favorite_color"},
            ),
        ]
        recipe = record_to_recipe(
            service_handle="airtable", origin="https://staging.airtable.com",
            name="signup", actions=actions,
        )
        assert "Review needed" in recipe.notes
        assert "favorite_color" in recipe.notes


# ───────────────────────── confirm-password reuse end-to-end ─────────────────────────


class TestConfirmPasswordReuse:
    def test_confirm_password_matches_persona_password(self):
        """The big one: a recorded recipe with password + confirm-password
        must, at replay time, fill BOTH fields with the SAME vault-backed
        persona password."""
        from core.foundry.replay import RecipeReplayer
        from core.foundry.vault import ResearchPersona
        from tests.unit.test_foundry_replay import MockDriver

        recipe = record_to_recipe(
            service_handle="airtable", origin="https://staging.airtable.com",
            name="signup",
            actions=[
                RecordedAction(action="navigate", url="https://staging.airtable.com/s"),
                RecordedAction(
                    action="fill", selector={"by": "name", "value": "password"},
                    field={"name": "password", "type": "password"},
                ),
                RecordedAction(
                    action="fill", selector={"by": "name", "value": "confirm"},
                    field={"name": "confirm_password", "type": "password"},
                ),
            ],
        )
        persona = ResearchPersona(
            persona_id="p", label="a", email="a@x", password="vault-password",
            first_name="A", last_name="B",
        )
        driver = MockDriver()

        async def never(ch):
            raise AssertionError("no challenge")

        outcome = _run(RecipeReplayer(driver).run(
            recipe, persona, challenge_handler=never,
        ))
        assert outcome.succeeded
        fills = driver.fills()
        # Both fields receive the exact password stored for this persona.
        assert len(fills) == 2
        assert fills[0]["value"] == fills[1]["value"]
        assert fills[0]["value"] == persona.password
