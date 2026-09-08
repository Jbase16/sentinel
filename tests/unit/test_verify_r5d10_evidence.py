"""Acceptance specimens for the standalone R5D10 evidence verifier."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from core.behavior.capability_effect_evidence import build_capability_effect_evidence
from core.behavior.capability_effect_promotion import (
    CAPABILITY_FINDING_PROMOTION_ENV,
)
from tests.unit.test_behavior_capability_effect_evidence import _run_result
from tests.unit.test_behavior_capability_effect_promotion import _completed_source


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "verify_r5d10_evidence.py"
EVIDENCE_ROOT_DOMAIN = b"sentinelforge:capability-effect-evidence:v1\x00"

pytestmark = pytest.mark.subprocess_spawn


def _promoted_specimen(tmp_path, monkeypatch):
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    config, receipts, service, admission, receipt, evidence, _twin = _completed_source(
        tmp_path, leak=True
    )
    status = service.promote(receipt.receipt_id)
    assert status.promotion_state == "promoted"
    journal = service.repository.load_capability_effect_admission(
        admission.admission_id
    )
    assert journal is not None
    receipt_path = receipts._path(receipt.fingerprint)
    cas_path = config.storage.evidence_path / "blobs" / journal["cas_blob_hash"]
    return {
        "config": config,
        "receipts": receipts,
        "service": service,
        "admission": admission,
        "receipt": receipt,
        "evidence": evidence,
        "journal": journal,
        "receipt_path": receipt_path,
        "cas_path": cas_path,
    }


def _run_verifier(specimen, *, cas_path=None):
    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
            "--receipt",
            str(specimen["receipt_path"]),
            "--database",
            str(specimen["config"].storage.db_path),
            "--cas-blob",
            str(cas_path or specimen["cas_path"]),
            "--execution-id",
            specimen["admission"].admission_id,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.stderr == ""
    return completed, json.loads(completed.stdout)


def _canonical_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _independent_evidence_root(value):
    preimage = dict(value)
    preimage.pop("evidence_root", None)
    return hashlib.sha256(EVIDENCE_ROOT_DOMAIN + _canonical_bytes(preimage)).hexdigest()


def test_verifier_is_stdlib_only_and_imports_no_production_authority():
    tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    assert not any(name == "core" or name.startswith("core.") for name in imported)
    assert not any(name == "tests" or name.startswith("tests.") for name in imported)
    completed = subprocess.run(
        [sys.executable, str(VERIFIER), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "--receipt" in completed.stdout
    assert "--database" in completed.stdout
    assert "--cas-blob" in completed.stdout


def test_independent_verifier_accepts_complete_promoted_specimen(
    tmp_path,
    monkeypatch,
):
    specimen = _promoted_specimen(tmp_path, monkeypatch)

    completed, report = _run_verifier(specimen)

    assert completed.returncode == 0
    assert report["overall_passed"] is True
    assert set(report["checks"]) == {
        "schema_validity",
        "integrity",
        "source_trust_mode",
        "replay_predicate",
        "original_identity_linkage",
        "canonical_correspondence",
    }
    assert all(item["passed"] for item in report["checks"].values())
    assert report["checks"]["replay_predicate"]["details"]["clauses"] == 11
    canonical = report["checks"]["canonical_correspondence"]["details"]
    assert canonical["journal_success_trusted_as_proof"] is False
    assert canonical["events_verified"] == 2


def test_independent_verifier_reports_cas_tamper_separately(
    tmp_path,
    monkeypatch,
):
    specimen = _promoted_specimen(tmp_path, monkeypatch)
    specimen["cas_path"].write_bytes(specimen["cas_path"].read_bytes() + b"\n")

    completed, report = _run_verifier(specimen)

    assert completed.returncode == 1
    assert report["overall_passed"] is False
    assert report["checks"]["schema_validity"]["passed"] is True
    assert report["checks"]["integrity"]["passed"] is False
    assert "digest" in report["checks"]["integrity"]["error"]
    assert report["checks"]["replay_predicate"]["passed"] is True


def test_independent_verifier_rejects_semantic_falsification_after_rehash(
    tmp_path,
    monkeypatch,
):
    specimen = _promoted_specimen(tmp_path, monkeypatch)
    admission = specimen["admission"]
    result, _twin = _run_result(
        leak_kind="no_capability_baseline",
        suffix="promotion-leak",
    )
    export = result.evidence_export()
    replacement = build_capability_effect_evidence(
        execution_export=export,
        source_receipt_id=specimen["receipt"].receipt_id,
        execution_admission_ref=admission.admission_id,
        assessment_session_id=admission.session_id,
        identity_binding=admission.identity_binding,
        target_origin=admission.target_origin,
        specification_ref=admission.specification_ref,
        operation_ref=admission.operation_ref,
        execution_policy=admission.execution_policy,
        conduct_provenance_root="3" * 64,
        producer_identity=admission.producer_identity,
        observed_at_epoch=max(
            float(item["observed_epoch"]) for item in export["terminal_receipts"]
        ),
        runtime_evidence_classification="controlled_in_memory_twin",
    )
    receipt_value = json.loads(specimen["receipt_path"].read_text(encoding="utf-8"))
    receipt_value["outcome"]["status"] = replacement.oracle["verdict"]
    receipt_value["outcome"]["capability_effect_evidence"] = replacement.to_dict()
    specimen["receipt_path"].write_text(
        json.dumps(receipt_value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    replacement_bytes = replacement.to_json_bytes()
    replacement_hash = hashlib.sha256(replacement_bytes).hexdigest()
    replacement_path = specimen["cas_path"].parent / replacement_hash
    replacement_path.write_bytes(replacement_bytes)
    with sqlite3.connect(specimen["config"].storage.db_path) as connection:
        connection.execute(
            """
            UPDATE capability_effect_promotion_journal
            SET evidence_root = ?, cas_blob_hash = ?
            WHERE admission_id = ?
            """,
            (
                replacement.evidence_root,
                replacement_hash,
                admission.admission_id,
            ),
        )

    completed, report = _run_verifier(specimen, cas_path=replacement_path)

    assert completed.returncode == 1
    assert report["checks"]["schema_validity"]["passed"] is True
    assert report["checks"]["integrity"]["passed"] is True
    assert report["checks"]["source_trust_mode"]["passed"] is True
    assert report["checks"]["original_identity_linkage"]["passed"] is True
    assert report["checks"]["replay_predicate"]["passed"] is False
    assert "clauses" in report["checks"]["replay_predicate"]["error"]
    assert report["checks"]["canonical_correspondence"]["passed"] is False


def test_independent_verifier_rejects_original_identity_substitution(
    tmp_path,
    monkeypatch,
):
    specimen = _promoted_specimen(tmp_path, monkeypatch)
    substituted = dict(specimen["journal"]["identity_data"])
    substituted["persona_id"] = "substituted-persona"
    with sqlite3.connect(specimen["config"].storage.db_path) as connection:
        connection.execute(
            """
            UPDATE capability_effect_promotion_journal
            SET identity_data = ?
            WHERE admission_id = ?
            """,
            (
                json.dumps(substituted, sort_keys=True, separators=(",", ":")),
                specimen["admission"].admission_id,
            ),
        )

    completed, report = _run_verifier(specimen)

    assert completed.returncode == 1
    assert report["checks"]["schema_validity"]["passed"] is True
    assert report["checks"]["integrity"]["passed"] is True
    assert report["checks"]["replay_predicate"]["passed"] is True
    assert report["checks"]["original_identity_linkage"]["passed"] is False
    assert (
        "original evidence context"
        in report["checks"]["original_identity_linkage"]["error"]
    )
    assert report["checks"]["canonical_correspondence"]["passed"] is True


def test_independent_verifier_rejects_rehashed_world_substitution(
    tmp_path,
    monkeypatch,
):
    specimen = _promoted_specimen(tmp_path, monkeypatch)
    receipt_value = json.loads(specimen["receipt_path"].read_text(encoding="utf-8"))
    replacement = receipt_value["outcome"]["capability_effect_evidence"]
    replacement["experiment_world_ref"] = (
        "world:" + hashlib.sha256(b"substituted-world").hexdigest()
    )
    replacement["evidence_root"] = _independent_evidence_root(replacement)
    specimen["receipt_path"].write_text(
        json.dumps(receipt_value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    replacement_bytes = _canonical_bytes(replacement)
    replacement_hash = hashlib.sha256(replacement_bytes).hexdigest()
    replacement_path = specimen["cas_path"].parent / replacement_hash
    replacement_path.write_bytes(replacement_bytes)
    with sqlite3.connect(specimen["config"].storage.db_path) as connection:
        connection.execute(
            """
            UPDATE capability_effect_promotion_journal
            SET evidence_root = ?, cas_blob_hash = ?
            WHERE admission_id = ?
            """,
            (
                replacement["evidence_root"],
                replacement_hash,
                specimen["admission"].admission_id,
            ),
        )

    completed, report = _run_verifier(specimen, cas_path=replacement_path)

    assert completed.returncode == 1
    assert report["checks"]["schema_validity"]["passed"] is False
    assert "world" in report["checks"]["schema_validity"]["error"]
    assert report["checks"]["integrity"]["passed"] is False
