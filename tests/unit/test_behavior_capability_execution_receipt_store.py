"""R5D7 durable capability-execution receipt store tests."""

from __future__ import annotations

import ast
from dataclasses import fields, replace
import json
import multiprocessing
import os
from pathlib import Path
import stat

import pytest

import core.behavior.capability_execution_receipt_store as store_module
from core.behavior.capability_confinement_freshness import (
    ConfinedPresentationBinding,
    ConfinementPresentation,
    evaluate_confinement,
)
from core.behavior.capability_consumption_ledger import (
    CapabilityConsumptionLedger,
    ConsumptionOutcome,
    evaluate_consumption,
)
from core.behavior.capability_contract import (
    CapabilityOutcome,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    classify_presentation,
)
from core.behavior.capability_execution_receipt import (
    CAPABILITY_EXECUTION_RECEIPT_MODE,
    CapabilityExecutionOutcome,
    CapabilityExecutionReceipt,
    evaluate_capability_execution,
)
from core.behavior.capability_execution_receipt_store import (
    CAPABILITY_EXECUTION_RECEIPT_STORE_ENV,
    CAPABILITY_EXECUTION_RECEIPT_STORE_MODE,
    CapabilityExecutionReceiptStore,
    CapabilityExecutionReceiptStoreError,
    DurableExecutionReceiptResult,
    StoredExecutionReceipt,
    persist_execution_receipt,
)
from core.behavior.capability_runtime_expiry import AdmittedRuntimeContract
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash
from core.behavior.receipts import _MAX_RECEIPT_BYTES


ORIGIN = "https://api.example.test"
ADMITTED_AT = 100.0
EXPIRES_AT = 200.0

OUTCOME_CASES = (
    (
        "completed",
        CapabilityOutcome.VALID,
        ConsumptionOutcome.FIRST_CONSUMPTION,
        150.0,
        CapabilityExecutionOutcome.EXECUTION_COMPLETED,
    ),
    (
        "inadmissible",
        CapabilityOutcome.WRONG_BINDING,
        ConsumptionOutcome.FIRST_CONSUMPTION,
        150.0,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE,
    ),
    (
        "already_consumed",
        CapabilityOutcome.VALID,
        ConsumptionOutcome.REPLAYED_PRESENTATION,
        150.0,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
    ),
    (
        "expired",
        CapabilityOutcome.VALID,
        ConsumptionOutcome.FIRST_CONSUMPTION,
        EXPIRES_AT,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
    ),
    (
        "not_live",
        CapabilityOutcome.VALID,
        ConsumptionOutcome.FIRST_CONSUMPTION,
        ADMITTED_AT - 1.0,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE,
    ),
)


def _owned_world(suffix: str = "alice") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", f"r5d7-{suffix}"),
        persona_ref=stable_hash("experiment_persona", f"r5d7-{suffix}"),
        ownership_ref=stable_hash("ownership_proof", f"r5d7-{suffix}"),
    )


def _contract(suffix: str = "alice") -> IssuedCapabilityContract:
    world = _owned_world(suffix)
    assert world.persona_ref is not None
    tenant_ref = stable_hash("owned_tenant", f"r5d7-{suffix}")
    tenant_ownership_ref = stable_hash(
        "ownership_proof",
        f"r5d7-{suffix}-tenant-owned",
    )
    return IssuedCapabilityContract.build(
        world=world,
        world_tenant_ref=tenant_ref,
        world_tenant_ownership_ref=tenant_ownership_ref,
        subject_ref=world.persona_ref,
        resource_ref=stable_hash("capability_resource", f"r5d7-{suffix}"),
        operation_ref=stable_hash("capability_operation", "download"),
        audience_ref=world.persona_ref,
        issuer_ref=stable_hash("capability_issuer", "r5d7-service"),
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        source_evidence_ref=stable_hash("source_evidence", f"r5d7-{suffix}"),
        secret_digest=stable_hash(
            "capability_secret_digest",
            f"r5d7-ephemeral-secret-{suffix}",
        ),
        issued_at_index=10,
        expires_at_index=20,
        max_uses=1,
        revocation_state=CapabilityRevocationState.ACTIVE,
    )


def _capture_records(*, suffix: str):
    object_id = f"r5d7-object-{suffix}"
    token = f"r5d7-token-{suffix}"
    return [
        {
            "method": "POST",
            "url": f"{ORIGIN}/api/exports",
            "request_body": '{"format":"json"}',
            "response_status": 201,
            "response_body": f'{{"id":"{object_id}","token":"{token}"}}',
        },
        {
            "method": "GET",
            "url": f"{ORIGIN}/api/exports/{object_id}",
            "headers": {"authorization": f"Bearer {token}"},
            "response_status": 200,
            "response_body": '{"ready":true}',
        },
    ]


def _presentation(
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


def _logical_decision(
    contract: IssuedCapabilityContract,
    outcome: CapabilityOutcome = CapabilityOutcome.VALID,
):
    overrides = {}
    if outcome is CapabilityOutcome.WRONG_BINDING:
        overrides["resource_ref"] = stable_hash("capability_resource", "wrong")
    decision = classify_presentation(contract, _presentation(contract, **overrides))
    assert decision.outcome is outcome
    return decision


def _binding(contract: IssuedCapabilityContract) -> ConfinedPresentationBinding:
    return ConfinedPresentationBinding.build(
        contract=contract,
        capability_ref=contract.capability_id,
        confined_world=contract._owned_world,
        confined_tenant_ref=contract.tenant_ref,
        confined_tenant_ownership_ref=contract.tenant_ownership_ref,
        target_origin=ORIGIN,
        prior_presentation_records=_capture_records(suffix="prior"),
        current_presentation_records=_capture_records(suffix="bound"),
    )


def _confinement_decision(
    contract: IssuedCapabilityContract,
    binding: ConfinedPresentationBinding,
    *,
    index: int,
):
    return evaluate_confinement(
        contract,
        binding,
        ConfinementPresentation.build(
            presented_world_ref=binding.confined_world_ref,
            presented_tenant_ref=binding.confined_tenant_ref,
            presented_tenant_ownership_ref=binding.confined_tenant_ownership_ref,
            presented_target_origin=ORIGIN,
            current_capture_records=_capture_records(suffix=f"presentation-{index}"),
        ),
    )


def _consumption_decision(
    contract: IssuedCapabilityContract,
    outcome: ConsumptionOutcome = ConsumptionOutcome.FIRST_CONSUMPTION,
):
    valid_decision = _logical_decision(contract)
    binding = _binding(contract)
    first_presentation = _confinement_decision(contract, binding, index=0)
    first = evaluate_consumption(
        contract,
        valid_decision,
        first_presentation,
        CapabilityConsumptionLedger.build(),
    )
    if outcome is ConsumptionOutcome.FIRST_CONSUMPTION:
        return first.decision
    if outcome is ConsumptionOutcome.REPLAYED_PRESENTATION:
        decision = evaluate_consumption(
            contract,
            valid_decision,
            first_presentation,
            first.ledger,
        ).decision
    else:
        decision = evaluate_consumption(
            contract,
            valid_decision,
            _confinement_decision(contract, binding, index=1),
            first.ledger,
        ).decision
    assert decision.outcome is outcome
    return decision


def _receipt(
    *,
    suffix: str = "alice",
    logical_outcome: CapabilityOutcome = CapabilityOutcome.VALID,
    consumption_outcome: ConsumptionOutcome = ConsumptionOutcome.FIRST_CONSUMPTION,
    now: float = 150.0,
) -> CapabilityExecutionReceipt:
    contract = _contract(suffix)
    return evaluate_capability_execution(
        _logical_decision(contract, logical_outcome),
        AdmittedRuntimeContract.build(
            contract=contract,
            capability_ref=contract.capability_id,
            runtime_ref=stable_hash("admitted_runtime", "r5d7-worker"),
            admitted_at_epoch=ADMITTED_AT,
            expires_at_epoch=EXPIRES_AT,
        ),
        _consumption_decision(contract, consumption_outcome),
        clock=lambda: now,
    )


def _receipt_for_case(case_name: str, *, suffix: str = "alice"):
    for name, logical, consumption, now, expected in OUTCOME_CASES:
        if name == case_name:
            receipt = _receipt(
                suffix=suffix,
                logical_outcome=logical,
                consumption_outcome=consumption,
                now=now,
            )
            assert receipt.outcome is expected
            return receipt
    raise AssertionError(f"unknown receipt case: {case_name}")


def _path_for(root: Path, receipt: CapabilityExecutionReceipt) -> Path:
    return root / CapabilityExecutionReceiptStore._file_name(
        receipt.capability_ref,
        receipt.receipt_id,
    )


def _write_canonical(path: Path, value) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _spawn_persist_worker(root: str, barrier, queue, now: float) -> None:
    try:
        receipt = _receipt(suffix="concurrent", now=now)
        barrier.wait(timeout=10)
        store = CapabilityExecutionReceiptStore(Path(root))
        result = store.persist(receipt)
        loaded = store.load(receipt.capability_ref)
        queue.put(
            (
                "ok",
                result.durable_written,
                receipt.receipt_id,
                tuple(record.receipt_id for record in loaded),
            )
        )
    except BaseException as exc:
        queue.put(("error", type(exc).__name__, str(exc)))


def _run_spawned_persists(root: Path, instants: tuple[float, float]):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    queue = context.Queue()
    processes = [
        context.Process(
            target=_spawn_persist_worker,
            args=(str(root), barrier, queue, now),
        )
        for now in instants
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _process in processes]
    queue.close()
    queue.join_thread()
    return results


@pytest.mark.parametrize(
    "case_name,expected",
    [(case[0], case[4]) for case in OUTCOME_CASES],
)
def test_all_terminal_outcomes_persist_through_one_append_only_path(
    tmp_path,
    case_name,
    expected,
):
    root = tmp_path / case_name
    receipt = _receipt_for_case(case_name)

    result = persist_execution_receipt(receipt, store_root=root)
    loaded = CapabilityExecutionReceiptStore(root).load(receipt.capability_ref)

    assert result.durable_written is True
    assert type(result.record) is StoredExecutionReceipt
    assert result.record.outcome is expected
    assert result.record.reloaded is True
    assert loaded == (result.record,)
    assert result.record.to_dict() == receipt.to_dict()
    assert result.record.observed_epoch == receipt.observed_epoch
    assert result.record.receipt_id == receipt.receipt_id


def test_persist_writes_canonical_owner_only_content_addressed_residue(tmp_path):
    root = tmp_path / "store"
    receipt = _receipt()

    result = CapabilityExecutionReceiptStore(root).persist(receipt)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    path = _path_for(root, receipt)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
    assert receipt.receipt_id in path.name
    payload = path.read_text(encoding="utf-8")
    value = json.loads(payload)
    assert payload == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value == receipt.to_dict()
    assert result.record.to_dict() == value
    assert not any(path.name.endswith(suffix) for suffix in (".tmp", ".reserve"))


def test_fresh_store_instance_loads_every_distinct_receipt_for_one_capability(
    tmp_path,
):
    root = tmp_path / "store"
    receipts = (
        _receipt(now=150.0),
        _receipt(now=151.0),
        _receipt(now=EXPIRES_AT),
    )
    first_store = CapabilityExecutionReceiptStore(root)
    results = tuple(first_store.persist(receipt) for receipt in receipts)

    loaded = CapabilityExecutionReceiptStore(root).load(receipts[0].capability_ref)

    assert all(result.durable_written for result in results)
    assert {record.receipt_id for record in loaded} == {
        receipt.receipt_id for receipt in receipts
    }
    assert {record.outcome for record in loaded} == {
        CapabilityExecutionOutcome.EXECUTION_COMPLETED,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
    }
    assert len(list(root.glob("*.json"))) == 3


def test_missing_root_loads_as_empty_without_creating_residue(tmp_path):
    root = tmp_path / "missing"
    receipt = _receipt()

    assert CapabilityExecutionReceiptStore(root).load(receipt.capability_ref) == ()
    assert not root.exists()


def test_idempotent_re_persist_preserves_exact_bytes_and_mtime(tmp_path):
    root = tmp_path / "store"
    receipt = _receipt_for_case("already_consumed")
    first = CapabilityExecutionReceiptStore(root).persist(receipt)
    path = _path_for(root, receipt)
    before = (path.read_bytes(), path.stat().st_mtime_ns)

    second = CapabilityExecutionReceiptStore(root).persist(receipt)
    after = (path.read_bytes(), path.stat().st_mtime_ns)

    assert first.durable_written is True
    assert second.durable_written is False
    assert second.record == first.record
    assert after == before
    assert len(list(root.glob("*.json"))) == 1


def test_capability_namespaces_load_independently(tmp_path):
    root = tmp_path / "store"
    receipt_a = _receipt(suffix="alice")
    receipt_b = _receipt(suffix="bob")
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt_a)
    store.persist(receipt_b)

    loaded_a = store.load(receipt_a.capability_ref)
    loaded_b = store.load(receipt_b.capability_ref)

    assert tuple(record.receipt_id for record in loaded_a) == (receipt_a.receipt_id,)
    assert tuple(record.receipt_id for record in loaded_b) == (receipt_b.receipt_id,)
    assert len(list(root.glob("*.json"))) == 2


def test_identical_spawned_writes_converge_idempotently(tmp_path):
    root = tmp_path / "store"

    results = _run_spawned_persists(root, (150.0, 150.0))

    assert all(result[0] == "ok" for result in results), results
    assert sorted(result[1] for result in results) == [False, True]
    assert len({result[2] for result in results}) == 1
    assert all(result[2] in result[3] for result in results)
    paths = list(root.glob("*.json"))
    assert len(paths) == 1
    payload = paths[0].read_text(encoding="utf-8")
    assert payload == json.dumps(
        json.loads(payload),
        sort_keys=True,
        separators=(",", ":"),
    )


def test_distinct_instant_spawned_writes_both_survive(tmp_path):
    root = tmp_path / "store"

    results = _run_spawned_persists(root, (150.0, 151.0))

    assert all(result[0] == "ok" for result in results), results
    assert [result[1] for result in results] == [True, True]
    receipt_ids = {result[2] for result in results}
    assert len(receipt_ids) == 2
    capability_ref = _receipt(suffix="concurrent").capability_ref
    loaded = CapabilityExecutionReceiptStore(root).load(capability_ref)
    assert {record.receipt_id for record in loaded} == receipt_ids
    assert len(list(root.glob("*.json"))) == 2


def test_store_root_configuration_uses_a_distinct_namespace(monkeypatch, tmp_path):
    override = tmp_path / "override"
    monkeypatch.setenv(CAPABILITY_EXECUTION_RECEIPT_STORE_ENV, str(override))
    assert CapabilityExecutionReceiptStore()._root() == override

    monkeypatch.delenv(CAPABILITY_EXECUTION_RECEIPT_STORE_ENV)
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
    assert CapabilityExecutionReceiptStore()._root() == (
        tmp_path / "data" / "capability_execution_receipts"
    )
    assert "behavioral_receipts" not in str(CapabilityExecutionReceiptStore()._root())
    assert "capability_consumptions" not in str(
        CapabilityExecutionReceiptStore()._root()
    )


def test_stored_projection_is_public_only_and_inert(tmp_path):
    result = CapabilityExecutionReceiptStore(tmp_path / "store").persist(_receipt())
    field_names = {field.name for field in fields(result.record)}

    assert field_names == {
        "receipt_id",
        "capability_ref",
        "liveness_ref",
        "consumption_ref",
        "observed_epoch",
        "outcome",
        "mode",
        "target_dispatch_authority",
        "execution_effect_authority",
        "finding_promotion_authority",
        "target_cleanup_authority",
        "reloaded",
    }
    assert not hasattr(result.record, "_liveness_decision")
    assert not hasattr(result.record, "_consumption_decision")
    assert "decision=" not in repr(result.record)
    assert result.record.reloaded is True


@pytest.mark.parametrize(
    "field_name",
    (
        "target_dispatch_authority",
        "execution_effect_authority",
        "finding_promotion_authority",
        "target_cleanup_authority",
    ),
)
def test_stored_projection_rejects_every_authority_flag(field_name):
    receipt = _receipt()
    record = StoredExecutionReceipt._from_dict(receipt.to_dict())

    with pytest.raises(ValueError, match="stored execution receipt is invalid"):
        replace(record, **{field_name: True})


@pytest.mark.parametrize(
    "changes,exception",
    (
        ({"reloaded": False}, ValueError),
        ({"mode": CAPABILITY_EXECUTION_RECEIPT_STORE_MODE}, ValueError),
        ({"outcome": "execution_completed"}, TypeError),
        ({"observed_epoch": 150}, ValueError),
        (
            {
                "receipt_id": stable_hash(
                    "capability_execution_receipt",
                    "forged",
                )
            },
            ValueError,
        ),
    ),
)
def test_stored_projection_rejects_non_inert_or_forged_values(changes, exception):
    record = StoredExecutionReceipt._from_dict(_receipt().to_dict())

    with pytest.raises(exception):
        replace(record, **changes)


def test_persist_rejects_non_receipts_and_subclasses_before_writing(tmp_path):
    root = tmp_path / "store"
    store = CapabilityExecutionReceiptStore(root)
    receipt = _receipt()

    class ReceiptSubclass(CapabilityExecutionReceipt):
        pass

    subclass = ReceiptSubclass(
        **{field.name: getattr(receipt, field.name) for field in fields(receipt)}
    )

    with pytest.raises(TypeError, match="must be a CapabilityExecutionReceipt"):
        store.persist(object())
    with pytest.raises(TypeError, match="must be a CapabilityExecutionReceipt"):
        store.persist(subclass)
    assert not root.exists()


def test_replace_revalidation_rejects_a_forged_in_memory_receipt(tmp_path):
    root = tmp_path / "store"
    receipt = _receipt()
    object.__setattr__(
        receipt,
        "outcome",
        CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
    )

    with pytest.raises(
        CapabilityExecutionReceiptStoreError,
        match="receipt is invalid",
    ):
        CapabilityExecutionReceiptStore(root).persist(receipt)
    assert not root.exists()


@pytest.mark.parametrize(
    "mutation",
    (
        "outcome",
        "capability_ref",
        "liveness_ref",
        "consumption_ref",
        "observed_epoch",
        "receipt_id",
    ),
)
def test_hand_edited_receipt_content_fails_closed(tmp_path, mutation):
    root = tmp_path / "store"
    receipt = _receipt()
    CapabilityExecutionReceiptStore(root).persist(receipt)
    path = _path_for(root, receipt)
    value = json.loads(path.read_text(encoding="utf-8"))

    replacements = {
        "outcome": CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED.value,
        "capability_ref": stable_hash("issued_capability_contract", "mutated"),
        "liveness_ref": stable_hash("runtime_liveness_decision", "mutated"),
        "consumption_ref": stable_hash(
            "capability_consumption_decision",
            "mutated",
        ),
        "observed_epoch": "151.0",
        "receipt_id": stable_hash("capability_execution_receipt", "mutated"),
    }
    value[mutation] = replacements[mutation]
    _write_canonical(path, value)

    with pytest.raises(CapabilityExecutionReceiptStoreError):
        CapabilityExecutionReceiptStore(root).load(receipt.capability_ref)


def test_filename_content_and_hash_three_way_binding_fails_closed(tmp_path):
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    original = _path_for(root, receipt)
    forged_id = stable_hash("capability_execution_receipt", "forged-name")
    forged = root / store._file_name(receipt.capability_ref, forged_id)
    forged.write_bytes(original.read_bytes())
    forged.chmod(0o600)

    with pytest.raises(
        CapabilityExecutionReceiptStoreError,
        match="name binding is invalid",
    ):
        store.load(receipt.capability_ref)


@pytest.mark.parametrize("epoch", ("150", "150.00"))
def test_hash_consistent_noncanonical_epoch_fails_closed(tmp_path, epoch):
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    path = _path_for(root, receipt)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["observed_epoch"] = epoch
    payload = {
        key: value[key]
        for key in (
            "capability_ref",
            "liveness_ref",
            "consumption_ref",
            "observed_epoch",
            "outcome",
            "mode",
        )
    }
    value["receipt_id"] = stable_hash("capability_execution_receipt", payload)
    forged_path = root / store._file_name(
        receipt.capability_ref,
        value["receipt_id"],
    )
    path.unlink()
    _write_canonical(forged_path, value)

    with pytest.raises(
        CapabilityExecutionReceiptStoreError,
        match="projection is invalid",
    ):
        store.load(receipt.capability_ref)


@pytest.mark.parametrize("encoding", ("whitespace", "key_order"))
def test_noncanonical_json_encoding_fails_closed(tmp_path, encoding):
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    path = _path_for(root, receipt)
    value = json.loads(path.read_text(encoding="utf-8"))
    if encoding == "whitespace":
        payload = json.dumps(value, indent=2, sort_keys=True)
    else:
        payload = json.dumps(
            dict(reversed(tuple(value.items()))),
            separators=(",", ":"),
        )
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(
        CapabilityExecutionReceiptStoreError,
        match="encoding is invalid",
    ):
        store.load(receipt.capability_ref)


@pytest.mark.parametrize(
    "mutation",
    ("schema", "extra_field", "outcome", "mode", "authority"),
)
def test_invalid_public_projection_fails_closed(tmp_path, mutation):
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    path = _path_for(root, receipt)
    value = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "schema":
        value["schema_version"] = 2
    elif mutation == "extra_field":
        value["live_context"] = "forbidden"
    elif mutation == "outcome":
        value["outcome"] = "unknown"
    elif mutation == "mode":
        value["mode"] = CAPABILITY_EXECUTION_RECEIPT_STORE_MODE
    else:
        value["target_dispatch_authority"] = True
    _write_canonical(path, value)

    with pytest.raises(CapabilityExecutionReceiptStoreError):
        store.load(receipt.capability_ref)


def test_collision_with_nonmatching_existing_bytes_fails_closed(tmp_path):
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    path = _path_for(root, receipt)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["target_cleanup_authority"] = True
    _write_canonical(path, value)

    with pytest.raises(CapabilityExecutionReceiptStoreError):
        store.persist(receipt)


def test_unsafe_file_mode_and_simulated_wrong_owner_fail_closed(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    path = _path_for(root, receipt)
    path.chmod(0o644)
    with pytest.raises(CapabilityExecutionReceiptStoreError, match="read safely"):
        store.load(receipt.capability_ref)

    path.chmod(0o600)
    actual_euid = os.geteuid()
    monkeypatch.setattr(store_module.os, "geteuid", lambda: actual_euid + 1)
    with pytest.raises(CapabilityExecutionReceiptStoreError, match="read safely"):
        CapabilityExecutionReceiptStore._read_record(
            path,
            expected_capability_ref=receipt.capability_ref,
            expected_receipt_id=receipt.receipt_id,
        )


def test_symlink_root_is_rejected_without_publishing(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "store"
    root.symlink_to(target, target_is_directory=True)

    with pytest.raises(CapabilityExecutionReceiptStoreError, match="root is unsafe"):
        CapabilityExecutionReceiptStore(root).persist(_receipt())
    assert list(target.iterdir()) == []


def test_preexisting_root_is_restricted_to_owner_only(tmp_path):
    root = tmp_path / "store"
    root.mkdir(mode=0o777)
    root.chmod(0o777)

    CapabilityExecutionReceiptStore(root).persist(_receipt())

    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_simulated_wrong_owner_root_fails_closed(tmp_path, monkeypatch):
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    receipt = _receipt()
    actual_euid = os.geteuid()
    monkeypatch.setattr(store_module.os, "geteuid", lambda: actual_euid + 1)

    with pytest.raises(CapabilityExecutionReceiptStoreError, match="root is unsafe"):
        CapabilityExecutionReceiptStore(root).load(receipt.capability_ref)


def test_oversized_file_fails_closed_before_json_decode(tmp_path):
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    path = _path_for(root, receipt)
    path.write_bytes(b"x" * (_MAX_RECEIPT_BYTES + 1))
    path.chmod(0o600)

    with pytest.raises(CapabilityExecutionReceiptStoreError, match="read safely"):
        store.load(receipt.capability_ref)


def test_persist_size_cap_fails_before_creating_root(tmp_path, monkeypatch):
    root = tmp_path / "store"
    monkeypatch.setattr(store_module, "_MAX_RECEIPT_BYTES", 1)

    with pytest.raises(CapabilityExecutionReceiptStoreError, match="size cap"):
        CapabilityExecutionReceiptStore(root).persist(_receipt())
    assert not root.exists()


def test_symlinked_receipt_file_fails_closed_via_no_follow(tmp_path):
    if not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("O_NOFOLLOW is unavailable")
    root = tmp_path / "store"
    receipt = _receipt()
    store = CapabilityExecutionReceiptStore(root)
    store.persist(receipt)
    path = _path_for(root, receipt)
    target = root / "target.json"
    target.write_bytes(path.read_bytes())
    target.chmod(0o600)
    path.unlink()
    path.symlink_to(target)

    with pytest.raises(CapabilityExecutionReceiptStoreError, match="read safely"):
        store.load(receipt.capability_ref)


@pytest.mark.parametrize(
    "capability_ref,exception",
    (
        (object(), TypeError),
        ("not-a-capability", ValueError),
        (stable_hash("wrong_prefix", "capability"), ValueError),
    ),
)
def test_load_rejects_invalid_capability_reference(
    tmp_path,
    capability_ref,
    exception,
):
    root = tmp_path / "store"
    with pytest.raises(exception):
        CapabilityExecutionReceiptStore(root).load(capability_ref)
    assert not root.exists()


def test_store_module_reuses_receipt_primitives_and_has_no_clock_or_transport():
    source_path = Path(store_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
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
        "subprocess",
        "time",
    } & (imported_modules | imported_from)
    assert imported_modules == {"json", "os"}
    assert imported_from == {
        "__future__",
        "capability_execution_receipt",
        "dataclasses",
        "pathlib",
        "receipts",
        "typing",
    }
    assert "BehavioralReceiptStore(root)._prepare_root()" in source
    for primitive in (
        "_validate_file_info",
        "_link_exclusive",
        "_fsync_directory",
    ):
        assert f"BehavioralReceiptStore.{primitive}" in source
    for imported_primitive in (
        "ReceiptStoreError",
        "_MAX_RECEIPT_BYTES",
        "re_full_sha256",
        "request_fingerprint",
    ):
        assert imported_primitive in source


def test_store_is_production_unwired_and_exports_only_its_public_surface():
    source_path = Path(store_module.__file__)
    repository_root = Path(__file__).resolve().parents[2]
    production_consumers = [
        path
        for path in (repository_root / "core").rglob("*.py")
        if path != source_path
        and "capability_execution_receipt_store" in path.read_text(encoding="utf-8")
    ]

    assert production_consumers == []
    assert store_module.__all__ == [
        "CAPABILITY_EXECUTION_RECEIPT_STORE_ENV",
        "CAPABILITY_EXECUTION_RECEIPT_STORE_MODE",
        "CapabilityExecutionReceiptStore",
        "CapabilityExecutionReceiptStoreError",
        "DurableExecutionReceiptResult",
        "StoredExecutionReceipt",
        "persist_execution_receipt",
    ]
    assert CAPABILITY_EXECUTION_RECEIPT_STORE_MODE == (
        "behavioral_capability_execution_receipt_store_v1"
    )
    assert CAPABILITY_EXECUTION_RECEIPT_MODE == (
        "behavioral_capability_execution_receipt_v1"
    )


def test_durable_result_requires_exact_inert_record_and_bool():
    record = StoredExecutionReceipt._from_dict(_receipt().to_dict())

    with pytest.raises(TypeError, match="record must be"):
        DurableExecutionReceiptResult(record=object(), durable_written=True)
    with pytest.raises(TypeError, match="durable_written must be"):
        DurableExecutionReceiptResult(record=record, durable_written=1)
