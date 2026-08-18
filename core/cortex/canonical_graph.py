"""Canonical causal graph sealed to one EvidenceLedger session revision."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional

from core.epistemic.ledger import (
    CanonicalSessionReadModel,
    load_canonical_session_read_model,
)

from .attack_path_contract import build_attack_path_contract
from .causal_graph import CausalGraphBuilder


@dataclass(frozen=True, init=False)
class CausalGraphSnapshot:
    """The exact graph truth consumed by UI, chat, triage, and reporting."""

    session_id: str
    evidence_revision: str
    _graph_dto_json: str
    _attack_path_contract_json: str

    def __init__(
        self,
        *,
        session_id: str,
        evidence_revision: str,
        graph_dto: Dict[str, Any],
        attack_path_contract: Dict[str, Any],
    ) -> None:
        graph_value = json.loads(
            json.dumps(graph_dto, sort_keys=True, separators=(",", ":"))
        )
        contract_value = json.loads(
            json.dumps(
                attack_path_contract,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        if (
            graph_value.get("session_id") != session_id
            or graph_value.get("evidence_revision") != evidence_revision
            or contract_value.get("session_id") != session_id
            or contract_value.get("evidence_revision") != evidence_revision
        ):
            raise ValueError("causal graph snapshot identity is inconsistent")
        expected = build_attack_path_contract(
            session_id=session_id,
            graph_dto=graph_value,
            evidence_revision=evidence_revision,
        )
        if expected != contract_value:
            raise ValueError("causal graph snapshot seal is invalid")
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "evidence_revision", evidence_revision)
        object.__setattr__(
            self,
            "_graph_dto_json",
            json.dumps(graph_value, sort_keys=True, separators=(",", ":")),
        )
        object.__setattr__(
            self,
            "_attack_path_contract_json",
            json.dumps(contract_value, sort_keys=True, separators=(",", ":")),
        )

    @property
    def graph_dto(self) -> Dict[str, Any]:
        return json.loads(self._graph_dto_json)

    @property
    def attack_path_contract(self) -> Dict[str, Any]:
        return json.loads(self._attack_path_contract_json)

    @property
    def graph_hash(self) -> str:
        return str(json.loads(self._attack_path_contract_json)["graph_hash"])


def build_causal_graph_snapshot(
    read_model: CanonicalSessionReadModel,
    *,
    issues: Optional[List[Dict[str, Any]]] = None,
) -> CausalGraphSnapshot:
    """Build graph truth only from active canonical findings and cited enrichment."""

    findings = read_model.finding_views()
    cited_issues = read_model.filter_cited_issues(list(issues or []))
    builder = CausalGraphBuilder()
    builder.build(findings)
    builder.enrich_from_issues(cited_issues)
    graph_dto = builder.export_dto(session_id=read_model.session_id)
    graph_dto["evidence_revision"] = read_model.revision
    contract = build_attack_path_contract(
        session_id=read_model.session_id,
        graph_dto=graph_dto,
        evidence_revision=read_model.revision,
    )
    graph_dto["graph_hash"] = contract["graph_hash"]
    return CausalGraphSnapshot(
        session_id=read_model.session_id,
        evidence_revision=read_model.revision,
        graph_dto=graph_dto,
        attack_path_contract=contract,
    )


async def load_causal_graph_snapshot(
    session_id: str,
    *,
    read_model: Optional[CanonicalSessionReadModel] = None,
    issues: Optional[List[Dict[str, Any]]] = None,
) -> CausalGraphSnapshot:
    """Load one fresh evidence revision and seal the causal graph to it."""

    canonical_view = read_model or load_canonical_session_read_model(session_id)
    if canonical_view.session_id != session_id:
        raise ValueError("causal graph session does not match evidence")
    issue_rows = issues
    if issue_rows is None:
        from core.data.db import Database

        db = Database.instance()
        await db.init()
        issue_rows = await db.get_issues(session_id)
    return build_causal_graph_snapshot(canonical_view, issues=issue_rows)
