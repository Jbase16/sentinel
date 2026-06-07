"""
core/foundry — the Persona Foundry (Phase 7).

The categorical innovation: close the gap between human interaction and
automation in account creation, WITHOUT bypassing anti-bot controls.

The insight nobody else acts on: most signup friction is BORING (typing,
navigating, reading verification emails). The anti-bot parts are RARE
(CAPTCHA, SMS code, payment 3DS). Every other tool refuses to automate
*any* of it because the rare-but-hard parts can't be cleanly automated.
The Foundry automates the boring 95% end-to-end and turns the rare 5%
into a FRICTIONLESS HUMAN HANDOFF — a one-second click instead of a
thirty-minute manual signup.

The researcher stays the agent of every consequential action:
  * They INTEND the signup (a recipe they recorded or approved).
  * They SOLVE any anti-bot challenge (via the handoff bus).
  * They OWN the email/phone used for verification (granted creds,
    never stolen).

Sentinel automates only the parts services don't care if you automate.

Components:
  recipe.py     — SignupRecipe: the parameterizable signup-flow artifact.
  vault.py      — PersonaVault: research-identity store + audit + rate
                  limit (the ethical backbone).
  replay.py     — RecipeReplayer: executes recipe + persona, pauses at
                  challenges.
  challenges.py — ChallengeBus: routes anti-bot walls to the human.
"""
from core.foundry.recipe import (
    BindingKind,
    ChallengeKind,
    RecipeStep,
    SignupRecipe,
    StepKind,
    resolve_binding,
)
from core.foundry.vault import (
    AccountCreationRecord,
    PersonaVault,
    RateLimitExceeded,
    ResearchPersona,
)
from core.foundry.replay import (
    Challenge,
    ChallengeResolution,
    Driver,
    RecipeReplayer,
    ReplayOutcome,
    ReplayState,
)
from core.foundry.challenges import (
    ChallengeBus,
    get_challenge_bus,
)

__all__ = [
    # recipe
    "BindingKind",
    "ChallengeKind",
    "RecipeStep",
    "SignupRecipe",
    "StepKind",
    "resolve_binding",
    # vault
    "AccountCreationRecord",
    "PersonaVault",
    "RateLimitExceeded",
    "ResearchPersona",
    # replay
    "Challenge",
    "ChallengeResolution",
    "Driver",
    "RecipeReplayer",
    "ReplayOutcome",
    "ReplayState",
    # challenge bus
    "ChallengeBus",
    "get_challenge_bus",
]
