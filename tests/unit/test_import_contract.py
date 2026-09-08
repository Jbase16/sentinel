"""Tests for semantic production-import consumer contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.import_contract import find_module_consumers, source_imports_module


TARGET = "core.behavior.capability_effect_evaluation"


@pytest.mark.parametrize(
    ("source", "current_module"),
    (
        (f"import {TARGET}\n", None),
        (f"import {TARGET} as effect\n", None),
        ("from core.behavior import capability_effect_evaluation\n", None),
        (f"from {TARGET} import CapabilityEffectObservation\n", None),
        ("from . import capability_effect_evaluation\n", "core.behavior.consumer"),
        (
            "from .capability_effect_evaluation import CapabilityEffectObservation\n",
            "core.behavior.consumer",
        ),
    ),
)
def test_static_import_forms_are_detected(
    source: str,
    current_module: str | None,
) -> None:
    assert source_imports_module(
        source,
        TARGET,
        current_module=current_module,
    )


@pytest.mark.parametrize(
    "source",
    (
        f'import importlib\nimportlib.import_module("{TARGET}")\n',
        f'import importlib as loader\nloader.import_module("{TARGET}")\n',
        f'from importlib import import_module\nimport_module("{TARGET}")\n',
        f'from importlib import import_module as load\nload("{TARGET}")\n',
        f'__import__("{TARGET}", fromlist=("CapabilityEffectObservation",))\n',
        (
            "import importlib\nimportlib.import_module("
            '".capability_effect_evaluation", package="core.behavior")\n'
        ),
        (f'import importlib\nMODULE = "{TARGET}"\nimportlib.import_module(MODULE)\n'),
        (
            'import importlib\nMODULE = "core.behavior." + '
            '"capability_effect_evaluation"\nimportlib.import_module(MODULE)\n'
        ),
    ),
)
def test_literal_dynamic_import_forms_are_detected(source: str) -> None:
    assert source_imports_module(source, TARGET)


@pytest.mark.parametrize(
    "source",
    (
        f"# import {TARGET}\n",
        f'"""Documentation mentions import {TARGET}."""\n',
        f'MODULE_DOCUMENTATION = "{TARGET}"\n',
        "capability_effect_evaluation_result = object()\n",
        f"import {TARGET}_extra\n",
        "from core.behavior import capability_effect_evaluation_extra\n",
        (f'def import_module(name):\n    return name\nimport_module("{TARGET}")\n'),
    ),
)
def test_textual_mentions_and_similarly_named_symbols_are_ignored(source: str) -> None:
    assert not source_imports_module(source, TARGET)


def test_find_module_consumers_uses_path_context_and_exclusions(
    tmp_path: Path,
) -> None:
    package = tmp_path / "core" / "behavior"
    package.mkdir(parents=True)
    source = package / "capability_effect_evaluation.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    static_consumer = package / "static_consumer.py"
    static_consumer.write_text(
        "from . import capability_effect_evaluation\n",
        encoding="utf-8",
    )
    dynamic_consumer = package / "dynamic_consumer.py"
    dynamic_consumer.write_text(
        f'import importlib\nimportlib.import_module("{TARGET}")\n',
        encoding="utf-8",
    )
    mention = package / "mention.py"
    mention.write_text(f'MODULE = "{TARGET}"\n', encoding="utf-8")

    consumers = find_module_consumers(
        package.glob("*.py"),
        TARGET,
        repository_root=tmp_path,
        exclude=(source,),
    )

    assert consumers == (dynamic_consumer, static_consumer)


def test_package_initializer_relative_import_uses_its_own_package(
    tmp_path: Path,
) -> None:
    package = tmp_path / "core" / "behavior"
    package.mkdir(parents=True)
    initializer = package / "__init__.py"
    initializer.write_text(
        "from . import capability_effect_evaluation\n",
        encoding="utf-8",
    )

    assert find_module_consumers(
        (initializer,),
        TARGET,
        repository_root=tmp_path,
    ) == (initializer,)
