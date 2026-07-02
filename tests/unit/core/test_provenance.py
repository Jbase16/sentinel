"""
Unit tests for the conduct provenance sink (core/safety/provenance).

This does NOT introduce a new ledger — it's a thin chain over the existing
core/replay MerkleEngine. The tests pin the properties a triager relies on:
determinism (same conduct → same root), redaction (hashes, never raw bodies),
tamper-evidence, and that policy DENIALS are recorded as strongly as sends.
"""

from core.safety.provenance import (
    ProvenanceEvent, ProvenanceSink, body_hash, response_shape,
)


def _ev(**kw):
    base = dict(method="GET", url_path="/api/x/1", action_class="CROSS_OBJECT_READ",
                policy_mode="bounty_safe", allowed=True, status=200)
    base.update(kw)
    return ProvenanceEvent(**base)


def _sink_with(events):
    s = ProvenanceSink()
    s.record_context(target="http://h", proof_mode="bounty_safe", policy_digest="pd1")
    for e in events:
        s.record_policy_action(e)
    return s


def test_recording_an_action_extends_the_chain_and_moves_the_root():
    s = ProvenanceSink()
    r0 = s.record_context(target="http://h", proof_mode="bounty_safe")
    r1 = s.record_policy_action(_ev())
    assert r0 != r1
    assert s.root() == r1                      # head is the latest block
    assert len(s.action_blocks) == 1
    assert s.verify()                          # every block id matches its content


def test_two_identical_sequences_produce_the_same_root():
    # The determinism guarantee — no timestamps sneak into the hashed payload.
    def make():
        return _sink_with([
            _ev(method="POST", url_path="/api/inv", action_class="OWNED_CREATE", status=201),
            _ev(url_path="/api/inv/1", status=403),
            _ev(method="PATCH", url_path="/api/me/profile", action_class="PRIVILEGE_MUTATION", status=200),
            _ev(url_path="/api/inv/1", status=200)])
    assert make().root() == make().root()


def test_changed_status_changes_the_root():
    a = _sink_with([_ev(status=200)])
    b = _sink_with([_ev(status=403)])
    assert a.root() != b.root()


def test_changed_response_hash_changes_the_root():
    a = _sink_with([_ev(response_body_hash=body_hash({"marker": "x"}))])
    b = _sink_with([_ev(response_body_hash=body_hash({"marker": "y"}))])
    assert a.root() != b.root()


def test_bodies_are_hashed_not_stored_raw():
    secret = {"tax_id_last4": "4242", "billing_email": "victim@example.com"}
    h = body_hash(secret)
    assert h.startswith("sha256:") and "4242" not in h and "victim" not in h
    # And the block payload carries only the hash + coarse shape, never the raw body.
    s = _sink_with([_ev(response_body_hash=h, response_summary=response_shape(secret))])
    payload = s.action_blocks[0].payload
    assert payload["response_body_hash"] == h
    assert "4242" not in str(payload) and "victim@example.com" not in str(payload)
    assert payload["response_summary"]["json_keys"] == ["billing_email", "tax_id_last4"]


def test_response_shape_is_conduct_only_no_marker_semantics():
    # The executor records SHAPE (keys), never whether a proof marker was present.
    shape = response_shape({"id": 1, "marker": "sf_secret"})
    assert shape["body_kind"] == "object" and "marker" in shape["json_keys"]
    assert "marker_present" not in shape and "sf_secret" not in str(shape)


def test_policy_denials_are_recorded_as_first_class_blocks():
    # A denied DESTRUCTIVE action is EVIDENCE — it proves the safety layer refused.
    s = _sink_with([
        _ev(method="DELETE", url_path="/api/users/7", action_class="DESTRUCTIVE",
            allowed=False, denial_reason="destructive_action_denied", status=None),
        _ev(status=200),
    ])
    summ = s.summary()
    assert summ["actions_denied_by_policy"] == 1
    assert summ["destructive_actions_denied"] == 1
    assert summ["destructive_actions_sent"] == 0
    assert summ["cross_object_reads_2xx"] == 1


def test_summary_and_event_range_reflect_conduct():
    s = _sink_with([
        _ev(method="POST", url_path="/api/inv", action_class="OWNED_CREATE", status=201),
        _ev(url_path="/api/inv/1", status=403),                        # pre-read denied by target
        _ev(method="PATCH", url_path="/api/me/profile", action_class="PRIVILEGE_MUTATION", status=200),
        _ev(url_path="/api/inv/1", status=200,
            budget_snapshot_after={"cross_object_reads": 1, "privilege_mutations": 1, "creates": 1}),
    ])
    summ = s.summary()
    assert summ["events"] == 4 and summ["actions_sent"] == 4
    assert summ["cross_object_reads_2xx"] == 1            # only the 200 read, not the 403
    assert summ["owned_test_accounts_only"] is True
    assert summ["format"] == "scan_capsule_merkle_dag"
    assert s.event_range() == {"start_seq": 1, "end_seq": 4}   # seq 0 is the context block


def test_owned_test_accounts_only_flips_false_on_real_data_access():
    s = _sink_with([_ev(target_is_researcher_owned=False, status=200)])
    assert s.summary()["owned_test_accounts_only"] is False


def test_empty_sink_has_no_root():
    assert ProvenanceSink().root() is None
