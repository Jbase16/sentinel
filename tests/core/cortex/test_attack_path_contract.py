from core.cortex.attack_path_contract import (
    build_attack_path_contract,
    is_attack_path_question,
    render_attack_path_response,
    sanitize_attack_path_claims,
)


def test_build_attack_path_contract_with_empty_chains():
    contract = build_attack_path_contract(
        session_id="sess-1",
        graph_dto={"attack_chains": []},
    )
    assert contract["session_id"] == "sess-1"
    assert contract["chain_count"] == 0
    assert contract["has_attack_paths"] is False
    assert contract["chains"] == []
    assert len(contract["graph_hash"]) == 64


def test_build_attack_path_contract_extracts_chain_fields():
    graph_dto = {
        "attack_chains": [
            {
                "id": "chain_1",
                "node_ids": ["f1", "f2"],
                "labels": ["Exposure", "Execution"],
                "length": 2,
                "score": 3.5,
                "entry_node": "f1",
                "leaf_node": "f2",
            }
        ]
    }
    contract = build_attack_path_contract(session_id="sess-2", graph_dto=graph_dto)
    assert contract["chain_count"] == 1
    assert contract["has_attack_paths"] is True
    assert contract["chain_ids"] == ["chain_1"]
    assert contract["chains"][0]["labels"] == ["Exposure", "Execution"]


def test_is_attack_path_question_heuristic():
    assert is_attack_path_question("Are there attack paths?") is True
    assert is_attack_path_question("Show exploit chain to compromise") is True
    assert is_attack_path_question("Summarize findings by severity") is False


def test_render_attack_path_response_uses_contract_truth():
    zero = {
        "session_id": "sess-z",
        "graph_hash": "a" * 64,
        "chain_count": 0,
        "chains": [],
    }
    text_zero = render_attack_path_response(zero)
    assert "0" in text_zero
    assert "No confirmed attack chain" in text_zero

    nonzero = {
        "session_id": "sess-n",
        "graph_hash": "b" * 64,
        "chain_count": 1,
        "chains": [
            {
                "id": "chain_1",
                "labels": ["Exposure", "Execution"],
                "node_ids": ["f1", "f2"],
            }
        ],
    }
    text_nonzero = render_attack_path_response(nonzero)
    assert "chain_1" in text_nonzero
    assert "Exposure -> Execution" in text_nonzero


def test_sanitize_attack_path_claims_replaces_attack_claims_when_graph_has_zero_paths():
    contract = build_attack_path_contract(session_id="sess-z", graph_dto={"attack_chains": []})
    text = "We confirmed an attack path from exposed admin to compromise."
    result = sanitize_attack_path_claims(text, contract)

    assert result["modified"] is True
    assert result["reason"] == "no_graph_paths"
    assert "Graph-validated attack paths for session sess-z: 0" in result["text"]


def test_sanitize_attack_path_claims_removes_claim_lines_without_chain_ids():
    contract = build_attack_path_contract(
        session_id="sess-3",
        graph_dto={
            "attack_chains": [
                {
                    "id": "chain_1",
                    "labels": ["Exposure", "Execution"],
                    "node_ids": ["f1", "f2"],
                    "length": 2,
                }
            ]
        },
    )
    text = (
        "Chain chain_1 is graph-validated.\n"
        "There is another attack path via debug endpoint."
    )
    result = sanitize_attack_path_claims(text, contract)

    assert result["modified"] is True
    assert result["removed_claims"] == 1
    assert "chain_1 is graph-validated" in result["text"]
    assert "another attack path" not in result["text"]
    assert "Reference graph chain IDs only: chain_1" in result["text"]


def test_sanitize_attack_path_claims_keeps_matching_count_statement():
    contract = build_attack_path_contract(
        session_id="sess-4",
        graph_dto={
            "attack_chains": [
                {"id": "chain_1", "node_ids": ["a", "b"], "length": 2},
                {"id": "chain_2", "node_ids": ["b", "c"], "length": 2},
            ]
        },
    )
    text = "There are 2 attack paths in the graph."
    result = sanitize_attack_path_claims(text, contract)

    assert result["modified"] is False
    assert result["reason"] == "compliant"
    assert result["text"] == text
