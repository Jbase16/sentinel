"""
core/foundry/recipe_store.py — persistence for SignupRecipes.

Recipes are durable, shareable artifacts: a signup flow recorded once
is replayed many times (different personas) and ideally shared across
researchers (the community-recipe-library effect). They live as JSON
under ~/.sentinelforge/recipes/, one file per recipe, keyed by
service handle + recipe id so the same service can have multiple
recipe versions.

Unlike the persona vault, recipes carry NO secrets — bindings
reference persona fields, they don't embed values. So recipe files are
safe to share / version-control / sync. (A recorded recipe that
accidentally captured a literal password would be a bug; the recorder
must use generated:/persona: bindings, never literal: for secrets.)
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from core.foundry.recipe import SignupRecipe

logger = logging.getLogger(__name__)


_STORE_ENV = "SENTINELFORGE_RECIPE_STORE"
_DEFAULT_STORE = Path.home() / ".sentinelforge" / "recipes"


def _store_dir() -> Path:
    override = os.environ.get(_STORE_ENV)
    if override:
        return Path(override)
    return _DEFAULT_STORE


def _path_for(recipe: SignupRecipe) -> Path:
    return _store_dir() / f"{recipe.service_handle}-{recipe.recipe_id}.json"


def save_recipe(recipe: SignupRecipe) -> Path:
    """Persist a recipe (atomic write). Validates first — refuses to
    save a malformed recipe so the store never holds garbage."""
    recipe.validate()
    recipe.derive_required_persona_fields()
    d = _store_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = _path_for(recipe)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(recipe.to_dict(), indent=2))
    tmp.replace(path)
    logger.info(
        "[recipe-store] saved %s (%s) → %s",
        recipe.name, recipe.recipe_id[:8], path,
    )
    return path


def load_recipe(recipe_id: str) -> Optional[SignupRecipe]:
    """Load a recipe by id (scans the store dir — ids are unique)."""
    d = _store_dir()
    if not d.exists():
        return None
    for p in d.glob(f"*-{recipe_id}.json"):
        try:
            return SignupRecipe.from_dict(json.loads(p.read_text()))
        except Exception as e:
            logger.error("[recipe-store] failed to load %s: %s", p, e)
            return None
    return None


def list_recipes(service_handle: Optional[str] = None) -> List[SignupRecipe]:
    """List recipes, optionally filtered to one service."""
    d = _store_dir()
    if not d.exists():
        return []
    pattern = f"{service_handle}-*.json" if service_handle else "*.json"
    out: List[SignupRecipe] = []
    for p in sorted(d.glob(pattern)):
        try:
            out.append(SignupRecipe.from_dict(json.loads(p.read_text())))
        except Exception as e:
            logger.warning("[recipe-store] skipping unreadable %s: %s", p, e)
    return out


def delete_recipe(recipe_id: str) -> bool:
    d = _store_dir()
    if not d.exists():
        return False
    removed = False
    for p in d.glob(f"*-{recipe_id}.json"):
        p.unlink()
        removed = True
    return removed
