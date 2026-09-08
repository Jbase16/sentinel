"""R5D4 durable capability-consumption store tests."""

from __future__ import annotations

import ast
import json
import multiprocessing
import os
from pathlib import Path
import stat

import pytest

import core.behavior.capability_consumption_store as store_module
from core.behavior.capability_confinement_freshness import (
    ConfinedPresentationBinding,
    ConfinementOutcome,
    ConfinementPresentation,
    evaluate_confinement,
)
from core.behavior.capability_consumption_ledger import (
    ConsumptionLedgerDenied,
    ConsumptionOutcome,
)
from core.behavior.capability_consumption_store import (
    CAPABILITY_CONSUMPTION_STORE_ENV,
    CAPABILITY_CONSUMPTION_STORE_MODE,
    CapabilityConsumptionStore,
    CapabilityConsumptionStoreError,
    record_consumption,
)
from core.behavior.capability_contract import (
    CapabilityOutcome,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    classify_presentation,
)
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash


ORIGIN = "https://api.example.test"
OTHER_ORIGIN = "https://other.example.test"
RAW_PRIOR_OBJECT = "r5d4-prior-object-0000"
RAW_PRIOR_TOKEN = "r5d4-prior-token-0000"
RAW_BOUND_OBJECT = "r5d4-bound-object-0000"
RAW_BOUND_TOKEN = "r5d4-bound-token-0000"


def _owned_world(suffix: str = "alice") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", f"r5d4-{suffix}"),
        persona_ref=stable_hash("experiment_persona", f"r5d4-{suffix}"),
        ownership_ref=stable_hash("ownership_proof", f"r5d4-{suffix}"),
    )


def _contract(
    *,
    suffix: str = "alice",
    max_uses: int = 1,
    revocation_state: CapabilityRevocationState = CapabilityRevocationState.ACTIVE,
) -> IssuedCapabilityContract:
    world = _owned_world(suffix)
    assert world.persona_ref is not None
    tenant_ref = stable_hash("owned_tenant", f"r5d4-{suffix}")
    tenant_ownership_ref = stable_hash(
        "ownership_proof",
        f"r5d4-{suffix}-tenant-owned",
    )
    return IssuedCapabilityContract.build(
        world=world,
        world_tenant_ref=tenant_ref,
        world_tenant_ownership_ref=tenant_ownership_ref,
        subject_ref=world.persona_ref,
        resource_ref=stable_hash("capability_resource", f"r5d4-{suffix}"),
        operation_ref=stable_hash("capability_operation", "download"),
        audience_ref=world.persona_ref,
        issuer_ref=stable_hash("capability_issuer", "r5d4-service"),
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        source_evidence_ref=stable_hash("source_evidence", f"r5d4-{suffix}"),
        secret_digest=stable_hash(
            "capability_secret_digest",
            f"r5d4-ephemeral-secret-{suffix}",
        ),
        issued_at_index=10,
        expires_at_index=20,
        max_uses=max_uses,
        revocation_state=revocation_state,
    )


def _records(
    *,
    origin: str = ORIGIN,
    object_id: str = RAW_BOUND_OBJECT,
    token: str = RAW_BOUND_TOKEN,
    status: int = 200,
):
    return [
        {
            "method": "POST",
            "url": f"{origin}/api/exports",
            "request_body": '{"format":"json"}',
            "response_status": 201,
            "response_body": f'{{"id":"{object_id}","token":"{token}"}}',
        },
        {
            "method": "GET",
            "url": f"{origin}/api/exports/{object_id}",
            "headers": {"authorization": f"Bearer {token}"},
            "response_status": status,
            "response_body": '{"ready":true}',
        },
    ]


def _logical_presentation(
    contract: IssuedCapabilityContract,
    **overrides,
) -> CapabilityPresentation:
    values = {
        "resource_ref": contract.resource_ref,
        "account_ref": contract.subject_ref,
        "audience_ref": contract.audience_ref,
        "operation_ref": contract.operation_ref,
        "at_index": contract.issued_at_index,
        "use_index": 0,
    }
    values.update(overrides)
    return CapabilityPresentation.build(**values)


def _binding(contract: IssuedCapabilityContract) -> ConfinedPresentationBinding:
    return ConfinedPresentationBinding.build(
        contract=contract,
        capability_ref=contract.capability_id,
        confined_world=contract._owned_world,
        confined_tenant_ref=contract.tenant_ref,
        confined_tenant_ownership_ref=contract.tenant_ownership_ref,
        target_origin=ORIGIN,
        prior_presentation_records=_records(
            object_id=RAW_PRIOR_OBJECT,
            token=RAW_PRIOR_TOKEN,
        ),
        current_presentation_records=_records(),
    )


def _confinement_decision(
    contract: IssuedCapabilityContract,
    binding: ConfinedPresentationBinding,
    *,
    index: int = 0,
    origin: str = ORIGIN,
    status: int = 200,
):
    presentation = ConfinementPresentation.build(
        presented_world_ref=binding.confined_world_ref,
        presented_tenant_ref=binding.confined_tenant_ref,
        presented_tenant_ownership_ref=binding.confined_tenant_ownership_ref,
        presented_target_origin=origin,
        current_capture_records=_records(
            origin=origin,
            object_id=f"r5d4-presentation-object-{index:04d}",
            token=f"r5d4-presentation-token-{index:04d}",
            status=status,
        ),
    )
    return evaluate_confinement(contract, binding, presentation)


def _admissible_context(
    *,
    suffix: str = "alice",
    max_uses: int = 1,
):
    contract = _contract(suffix=suffix, max_uses=max_uses)
    capability_decision = classify_presentation(
        contract,
        _logical_presentation(contract),
    )
    return contract, capability_decision, _binding(contract)


def _record(
    root: Path,
    *,
    suffix: str = "alice",
    max_uses: int = 1,
    index: int = 0,
):
    contract, capability_decision, binding = _admissible_context(
        suffix=suffix,
        max_uses=max_uses,
    )
    confinement_decision = _confinement_decision(
        contract,
        binding,
        index=index,
    )
    return (
        record_consumption(
            contract,
            capability_decision,
            confinement_decision,
            store_root=root,
        ),
        contract,
        capability_decision,
        confinement_decision,
    )


def _snapshot(root: Path):
    return {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(root.iterdir())
    }


class _InterleavedConsumptionStore(CapabilityConsumptionStore):
    def __init__(self, root: Path, barrier) -> None:
        super().__init__(root)
        self._publish_barrier = barrier

    def _publish_state(self, root, state) -> None:
        self._publish_barrier.wait(timeout=10)
        super()._publish_state(root, state)


def _concurrent_record_worker(root: str, barrier, queue) -> None:
    try:
        contract, capability_decision, binding = _admissible_context()
        result = _InterleavedConsumptionStore(Path(root), barrier).record_consumption(
            contract,
            capability_decision,
            _confinement_decision(contract, binding),
        )
        queue.put(
            (
                "ok",
                result.decision.outcome.value,
                result.durable_state_written,
            )
        )
    except BaseException as exc:
        queue.put(("error", type(exc).__name__, str(exc)))


def test_first_consumption_writes_canonical_safe_local_residue(tmp_path):
    root = tmp_path / "store"
    result, contract, _, _ = _record(root)

    assert result.decision.outcome is ConsumptionOutcome.FIRST_CONSUMPTION
    assert result.durable_state_written is True
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    paths = list(root.iterdir())
    assert len(paths) == 1
    path = paths[0]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
    assert result.store_key in path.name
    payload = path.read_text(encoding="utf-8")
    value = json.loads(payload)
    assert payload == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["mode"] == CAPABILITY_CONSUMPTION_STORE_MODE
    assert value["capability_ref"] == contract.capability_id
    assert value["use_slot"] == 0
    assert value["ledger"]["ledger_id"] == result.ledger.ledger_id
    assert not any(path.name.endswith(suffix) for suffix in (".tmp", ".reserve"))
    for raw_value in (
        RAW_PRIOR_OBJECT,
        RAW_PRIOR_TOKEN,
        RAW_BOUND_OBJECT,
        RAW_BOUND_TOKEN,
        "r5d4-ephemeral-secret-alice",
        "r5d4-presentation-token-0000",
    ):
        assert raw_value not in payload

    loaded = CapabilityConsumptionStore(root).load(contract)
    assert loaded == result.ledger
    assert loaded.entries[0].reloaded is True


def test_restart_survival_distinguishes_replay_and_single_use_exhaustion(tmp_path):
    root = tmp_path / "store"
    _record(root, max_uses=1, index=0)
    contract, capability_decision, binding = _admissible_context(max_uses=1)
    restarted = CapabilityConsumptionStore(root)

    replay = restarted.record_consumption(
        contract,
        capability_decision,
        _confinement_decision(contract, binding, index=0),
    )
    exhausted = CapabilityConsumptionStore(root).record_consumption(
        contract,
        capability_decision,
        _confinement_decision(contract, binding, index=1),
    )

    assert replay.decision.outcome is ConsumptionOutcome.REPLAYED_PRESENTATION
    assert exhausted.decision.outcome is (
        ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED
    )
    assert replay.durable_state_written is False
    assert exhausted.durable_state_written is False


@pytest.mark.subprocess_spawn
def test_single_use_is_atomic_across_spawned_processes(tmp_path):
    root = tmp_path / "store"
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    queue = context.Queue()
    processes = [
        context.Process(
            target=_concurrent_record_worker,
            args=(str(root), barrier, queue),
        )
        for _index in range(2)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _index in processes]

    assert all(result[0] == "ok" for result in results), results
    assert sorted(result[1] for result in results) == sorted(
        (
            ConsumptionOutcome.FIRST_CONSUMPTION.value,
            ConsumptionOutcome.REPLAYED_PRESENTATION.value,
        )
    )
    assert sorted(result[2] for result in results) == [False, True]
    assert len(list(root.glob("*.json"))) == 1


def test_multi_use_budget_and_precedence_survive_repeated_restarts(tmp_path):
    root = tmp_path / "store"
    for index in range(3):
        result, _, _, _ = _record(root, max_uses=3, index=index)
        assert result.decision.outcome is ConsumptionOutcome.FIRST_CONSUMPTION
        assert result.durable_state_written is True

    contract, capability_decision, binding = _admissible_context(max_uses=3)
    replay = CapabilityConsumptionStore(root).record_consumption(
        contract,
        capability_decision,
        _confinement_decision(contract, binding, index=0),
    )
    exhausted = CapabilityConsumptionStore(root).record_consumption(
        contract,
        capability_decision,
        _confinement_decision(contract, binding, index=3),
    )

    assert replay.decision.outcome is ConsumptionOutcome.REPLAYED_PRESENTATION
    assert exhausted.decision.outcome is (
        ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED
    )
    assert sorted(entry.use_slot for entry in replay.ledger.entries) == [0, 1, 2]
    assert len(list(root.glob("*.json"))) == 3


def test_replay_and_exhaustion_leave_bytes_and_mtimes_unchanged(tmp_path):
    root = tmp_path / "store"
    _record(root, max_uses=1, index=0)
    before = _snapshot(root)

    replay, _, _, _ = _record(root, max_uses=1, index=0)
    after_replay = _snapshot(root)
    exhausted, _, _, _ = _record(root, max_uses=1, index=1)
    after_exhaustion = _snapshot(root)

    assert replay.decision.outcome is ConsumptionOutcome.REPLAYED_PRESENTATION
    assert exhausted.decision.outcome is (
        ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED
    )
    assert before == after_replay == after_exhaustion


@pytest.mark.parametrize(
    "inadmissible",
    (
        "wrong_binding",
        "expired",
        "revoked",
        "already_used",
        "escaped",
        "stale",
        "logical_capability_mismatch",
        "confinement_capability_mismatch",
    ),
)
def test_inadmissible_axes_fail_before_creating_store_state(tmp_path, inadmissible):
    root = tmp_path / "store"
    contract = _contract(
        revocation_state=(
            CapabilityRevocationState.REVOKED
            if inadmissible == "revoked"
            else CapabilityRevocationState.ACTIVE
        )
    )
    overrides = {}
    if inadmissible == "wrong_binding":
        overrides["resource_ref"] = stable_hash("capability_resource", "wrong")
    elif inadmissible == "expired":
        overrides["at_index"] = contract.expires_at_index
    elif inadmissible == "already_used":
        overrides["use_index"] = contract.max_uses
    capability_decision = classify_presentation(
        contract,
        _logical_presentation(contract, **overrides),
    )
    binding = _binding(contract)
    confinement_decision = _confinement_decision(
        contract,
        binding,
        origin=(OTHER_ORIGIN if inadmissible == "escaped" else ORIGIN),
        status=(409 if inadmissible == "stale" else 200),
    )
    if inadmissible == "logical_capability_mismatch":
        other, capability_decision, _ = _admissible_context(suffix="bob")
        assert other.capability_id != contract.capability_id
    elif inadmissible == "confinement_capability_mismatch":
        other, _, other_binding = _admissible_context(suffix="bob")
        confinement_decision = _confinement_decision(other, other_binding)

    assert (
        capability_decision.outcome is not CapabilityOutcome.VALID
        or confinement_decision.outcome is not ConfinementOutcome.CONFINED_FRESH
        or capability_decision.capability_id != contract.capability_id
        or confinement_decision.capability_ref != contract.capability_id
    )
    with pytest.raises(
        ConsumptionLedgerDenied,
        match="capability_use_is_not_admissible",
    ):
        record_consumption(
            contract,
            capability_decision,
            confinement_decision,
            store_root=root,
        )

    assert not root.exists()


@pytest.mark.parametrize(
    "mutation",
    (
        "mutated_ref",
        "injected_replay_key",
        "forged_entry_id",
        "forged_ledger_id",
        "injected_entry",
    ),
)
def test_hand_edited_durable_state_fails_closed_on_load(tmp_path, mutation):
    root = tmp_path / "store"
    _, contract, _, _ = _record(root)
    path = next(root.glob("*.json"))
    value = json.loads(path.read_text(encoding="utf-8"))
    entry = value["ledger"]["entries"][0]

    if mutation == "mutated_ref":
        entry["capability_decision_ref"] = stable_hash(
            "capability_decision",
            "mutated",
        )
    elif mutation == "injected_replay_key":
        injected = stable_hash("capability_confinement_decision", "injected")
        entry["presentation_ref"] = injected
        entry["confinement_decision_ref"] = injected
    elif mutation == "forged_entry_id":
        entry["entry_id"] = stable_hash("capability_consumption_entry", "forged")
    elif mutation == "forged_ledger_id":
        value["ledger"]["ledger_id"] = stable_hash(
            "capability_consumption_ledger",
            "forged",
        )
    else:
        injected_entry = dict(entry)
        injected_entry["use_slot"] = 1
        value["ledger"]["entries"].append(injected_entry)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(CapabilityConsumptionStoreError):
        CapabilityConsumptionStore(root).load(contract)


def test_unsafe_file_mode_and_simulated_wrong_owner_fail_closed(tmp_path, monkeypatch):
    root = tmp_path / "store"
    _, contract, _, _ = _record(root)
    path = next(root.glob("*.json"))
    path.chmod(0o644)
    with pytest.raises(CapabilityConsumptionStoreError, match="read safely"):
        CapabilityConsumptionStore(root).load(contract)

    path.chmod(0o600)
    actual_euid = os.geteuid()
    monkeypatch.setattr(store_module.os, "geteuid", lambda: actual_euid + 1)
    with pytest.raises(CapabilityConsumptionStoreError, match="read safely"):
        CapabilityConsumptionStore._read_state(
            path,
            contract=contract,
            expected_slot=0,
        )


def test_symlink_root_is_rejected_without_publishing_state(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "store"
    root.symlink_to(target, target_is_directory=True)

    with pytest.raises(CapabilityConsumptionStoreError, match="root is unsafe"):
        _record(root)
    assert list(target.iterdir()) == []


def test_preexisting_store_root_is_restricted_to_owner_only(tmp_path):
    root = tmp_path / "store"
    root.mkdir(mode=0o777)
    root.chmod(0o777)

    _record(root)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_store_root_configuration_is_isolated(monkeypatch, tmp_path):
    override = tmp_path / "override"
    monkeypatch.setenv(CAPABILITY_CONSUMPTION_STORE_ENV, str(override))
    assert CapabilityConsumptionStore()._root() == override

    monkeypatch.delenv(CAPABILITY_CONSUMPTION_STORE_ENV)
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
    assert CapabilityConsumptionStore()._root() == (
        tmp_path / "data" / "capability_consumptions"
    )


def test_capabilities_are_persisted_and_loaded_independently(tmp_path):
    root = tmp_path / "store"
    _, contract_a, _, _ = _record(root, suffix="alice")
    _, contract_b, _, _ = _record(root, suffix="bob")

    ledger_a = CapabilityConsumptionStore(root).load(contract_a)
    ledger_b = CapabilityConsumptionStore(root).load(contract_b)

    assert {entry.capability_ref for entry in ledger_a.entries} == {
        contract_a.capability_id
    }
    assert {entry.capability_ref for entry in ledger_b.entries} == {
        contract_b.capability_id
    }
    assert len(list(root.glob("*.json"))) == 2


def test_store_module_has_no_target_network_clock_or_production_wiring():
    source_path = Path(store_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_from = {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not {
        "asyncio",
        "httpx",
        "requests",
        "socket",
        "time",
    } & (imported_modules | imported_from)

    repository_root = Path(__file__).resolve().parents[2]
    production_consumers = [
        path
        for path in (repository_root / "core").rglob("*.py")
        if path != source_path
        and "capability_consumption_store" in path.read_text(encoding="utf-8")
    ]
    assert production_consumers == []
