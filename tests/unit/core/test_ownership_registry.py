"""
Unit tests for the proof-backed ownership registry (core/safety/ownership_registry).

These pin the property that replaces the caller's word with evidence: a ref is
"researcher-owned" ONLY if a researcher persona provably created it here. The
security-critical cases are the fail-closed ones — unregistered refs, cross-collection
id collisions, and foreign origins must all be rejected.
"""

import pytest

from core.safety.ownership_registry import (
    NativeOwnedCreationWitness,
    OwnershipRegistry,
)


def _reg(create_url, response, **kw):
    r = OwnershipRegistry()
    r.register_created(create_url, response, **kw)
    return r


def test_created_object_is_owned_for_its_byid_read():
    # The composed-proof shapes: B creates in a workspace-scoped collection, the by-id
    # read is collection + "/{id}". The registry links them by (origin, noun, id).
    r = _reg("http://h/api/workspaces/wsB/invoices", {"id": "inv_1", "marker": "x"},
             actor_persona="B")
    assert r.is_owned("http://h/api/workspaces/wsB/invoices/inv_1")
    assert r.owner_of("http://h/api/workspaces/wsB/invoices/inv_1") == "B"
    assert len(r) == 1


def test_unregistered_ref_is_not_owned():
    r = _reg("http://h/api/invoices", {"id": "inv_1"})
    assert not r.is_owned("http://h/api/invoices/inv_2")     # different id
    assert not r.is_owned("http://h/api/invoices")           # the collection itself


def test_same_id_in_a_different_collection_is_not_owned():
    # SECURITY: a created invoice's id must not vouch for a same-id document.
    r = _reg("http://h/api/workspaces/wsB/invoices", {"id": "5"})
    assert r.is_owned("http://h/api/workspaces/wsB/invoices/5")
    assert not r.is_owned("http://h/api/workspaces/wsB/documents/5")


def test_foreign_origin_is_not_owned():
    r = _reg("http://h/api/invoices", {"id": "inv_1"})
    assert not r.is_owned("http://evil/api/invoices/inv_1")


def test_create_without_an_id_registers_nothing():
    r = OwnershipRegistry()
    assert r.register_created("http://h/api/invoices", {"ok": True}) is None
    assert len(r) == 0 and not r.is_owned("http://h/api/invoices/anything")


def test_id_extracted_from_list_and_data_envelope():
    assert _reg("http://h/api/notes", [{"id": "note_9"}]).is_owned("http://h/api/notes/note_9")
    assert _reg("http://h/api/notes", {"data": {"id": "note_9"}}).is_owned("http://h/api/notes/note_9")


def test_numeric_ids_are_matched_as_strings():
    r = _reg("http://h/api/Baskets", {"id": 7})
    assert r.is_owned("http://h/api/Baskets/7")
    assert not r.is_owned("http://h/api/Baskets/8")


def test_native_witness_registers_only_the_exact_persona_destination():
    destination_ref = "interaction_destination:" + "d" * 64
    witness = NativeOwnedCreationWitness(
        persona_id="a" * 32,
        create_ref="interaction_creation:" + "c" * 64,
        destination_ref=destination_ref,
        proof_ref="native_ownership_witness:" + "e" * 64,
    )
    registry = OwnershipRegistry()

    assert registry.register_native_witnessed_read(
        "https://example.test/documents/doc-owned",
        witness,
        actor_persona="a" * 32,
        destination_ref=destination_ref,
    ) == ("https://example.test", "documents", "doc-owned")
    assert registry.owner_of(
        "https://example.test/documents/doc-owned"
    ) == "a" * 32

    other = OwnershipRegistry()
    assert other.register_native_witnessed_read(
        "https://example.test/documents/doc-owned",
        witness,
        actor_persona="b" * 32,
        destination_ref=destination_ref,
    ) is None
    assert other.register_native_witnessed_read(
        "https://example.test/documents/doc-owned",
        witness,
        actor_persona="a" * 32,
        destination_ref="interaction_destination:" + "f" * 64,
    ) is None
    assert not other.is_owned(
        "https://example.test/documents/doc-owned"
    )


def test_native_witness_rejects_malformed_contract_fields():
    with pytest.raises(ValueError, match="witness is invalid"):
        NativeOwnedCreationWitness(
            persona_id="alice",
            create_ref="interaction_creation:" + "c" * 64,
            destination_ref="interaction_destination:" + "d" * 64,
            proof_ref="native_ownership_witness:" + "e" * 64,
        )
