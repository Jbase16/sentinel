"""
core/safety/ownership_registry.py

Proof-backed object ownership for the bounty-safe envelope.

The last "trust me bro" hole: the CROSS_OBJECT_READ gate trusted the caller's
`target_is_researcher_owned=True`. A proof module could set that flag on ANY ref.
This registry replaces the assertion with EVIDENCE — an object ref counts as
researcher-owned only if a researcher persona provably CREATED it earlier in this
session, observed at the executor seam from a real 2xx OWNED_CREATE response (not
claimed by a module).

The key is (origin, collection_noun, object_id): the server-assigned id, scoped to
the collection it was created in, so a created invoice's id can't vouch for a same-id
document. Because both owned_proof and minimal_amplification read via an OpenAPI by-id
SIBLING of the create collection (collection + "/{id}"), the read's noun-before-id
equals the create collection's last segment — so the key matches without the executor
needing to know the by-id template in advance. Unknown/mismatched refs fail closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlparse

from core.safety.ownership_locator import (
    LocatorOwnershipDenied,
    LocatorOwnershipProof,
    LocatorOwnershipVerification,
    OwnedRequestLocatorKind,
    build_locator_proof,
    extract_locator_value,
    proof_material,
    request_origin,
    seal_matches,
)

Key = Tuple[str, str, str]   # (origin, collection_noun, object_id)

_DESTINATION_REF = re.compile(r"^interaction_destination:[0-9a-f]{64}$")
_CREATION_REF = re.compile(r"^interaction_creation:[0-9a-f]{64}$")
_PROOF_REF = re.compile(r"^native_ownership_witness:[0-9a-f]{64}$")
_PERSONA_ID = re.compile(r"^[0-9a-f]{32}$")
_OWNERSHIP_EXPERIMENT_PROOF_REF = re.compile(
    r"^ownership_experiment_proof:[0-9a-f]{64}$"
)
_OWNERSHIP_EXPERIMENT_ROLE_REF = re.compile(
    r"^ownership_experiment_role:[0-9a-f]{64}$"
)
_CAPTURE_DIGEST = re.compile(r"^capture_set:[0-9a-f]{64}$")


def _origin(url: str) -> str:
    try:
        p = urlparse(url if "://" in url else "http://" + url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return ""


def _segments(url: str) -> list:
    try:
        return [s for s in (urlparse(url).path or "").split("/") if s]
    except Exception:
        return []


def _extract_id(resp: Any) -> Optional[Any]:
    """The server-assigned object id from a create response (dict, list-of-one, or a
    {'data': ...} envelope). Deliberately compact — no wraith dependency."""
    if isinstance(resp, dict):
        for k, v in resp.items():
            if str(k).lower() == "id" and v is not None:
                return v
        inner = resp.get("data")
        if isinstance(inner, (dict, list)):
            return _extract_id(inner)
    elif isinstance(resp, list) and resp:
        return _extract_id(resp[0])
    return None


def _created_key(create_url: str, object_id: Any) -> Optional[Key]:
    segs = _segments(create_url)
    if not segs or object_id is None:
        return None
    return (_origin(create_url), segs[-1].lower(), str(object_id))


def _read_key(read_url: str) -> Optional[Key]:
    segs = _segments(read_url)
    if len(segs) < 2:                       # need at least .../<collection>/<id>
        return None
    return (_origin(read_url), segs[-2].lower(), str(segs[-1]))


@dataclass(frozen=True)
class NativeOwnedCreationWitness:
    """Authenticated native evidence for one UI-created object destination.

    Construction belongs to the driver bridge after it verifies the HMAC made
    by the retained persona window. The registry still rebinds the witness to
    the acting persona and exact resolved read URL before accepting ownership.
    """

    persona_id: str
    create_ref: str
    destination_ref: str
    proof_ref: str

    def __post_init__(self) -> None:
        if (
            _PERSONA_ID.fullmatch(self.persona_id) is None
            or _CREATION_REF.fullmatch(self.create_ref) is None
            or _DESTINATION_REF.fullmatch(self.destination_ref) is None
            or _PROOF_REF.fullmatch(self.proof_ref) is None
        ):
            raise ValueError("native owned creation witness is invalid")


@dataclass
class OwnershipRegistry:
    """Session-scoped, in-memory record of objects researcher personas created here.
    Not exported/redacted like the provenance sink — this is an internal authorization
    structure the policy consults; it may hold raw ids."""

    _owned: Dict[Key, Dict[str, Any]] = field(default_factory=dict)
    _seal_key: bytes = field(
        default_factory=lambda: secrets.token_bytes(32),
        repr=False,
        compare=False,
    )

    @property
    def registry_ref(self) -> str:
        """Opaque identity for this session-local registry instance."""

        return f"ownership_registry:{hashlib.sha256(self._seal_key).hexdigest()}"

    def transport_context_ref(self, headers: Mapping[str, Any]) -> str:
        """HMAC one replay-header context without exposing guessable raw hashes."""

        if not isinstance(headers, Mapping):
            raise LocatorOwnershipDenied(
                "locator_transport_context_is_invalid"
            )
        normalized = tuple(
            sorted(
                ((str(key), str(value)) for key, value in headers.items()),
                key=lambda item: (item[0].lower(), item[0]),
            )
        )
        lowered = [key.lower() for key, _ in normalized]
        if len(lowered) != len(set(lowered)):
            raise LocatorOwnershipDenied(
                "locator_transport_context_is_ambiguous"
            )
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = hmac.new(
            self._seal_key,
            b"locator_transport_context\x00" + encoded,
            hashlib.sha256,
        ).hexdigest()
        return f"locator_transport_context:{digest}"

    def register_created(self, create_url: str, response: Any, *,
                         actor_persona: Optional[str] = None) -> Optional[Key]:
        """Record that a researcher persona created an object here, from a 2xx create
        response. Returns the key, or None if no id could be extracted."""
        key = _created_key(create_url, _extract_id(response))
        if key is None:
            return None
        self._owned[key] = {"actor_persona": actor_persona,
                            "collection": key[1], "object_id": key[2]}
        return key

    def register_created_value(
        self,
        create_url: str,
        object_id: Any,
        *,
        actor_persona: Optional[str] = None,
    ) -> Optional[Key]:
        """Register an exact ID extracted from a successful create response.

        This supports nonstandard response fields such as ``noteId``. Callers must
        invoke it only after the executor observed a successful ``OWNED_CREATE``;
        the registry remains an in-memory policy structure, not caller evidence.
        """

        key = _created_key(create_url, object_id)
        if key is None:
            return None
        self._owned[key] = {
            "actor_persona": actor_persona,
            "collection": key[1],
            "object_id": key[2],
        }
        return key

    def unregister_created_value(
        self,
        create_url: str,
        object_id: Any,
        *,
        actor_persona: Optional[str] = None,
    ) -> bool:
        """Remove one exact ownership grant after verified cleanup.

        A mismatched actor cannot revoke another persona's grant. Callers must
        invoke this only after the corresponding cleanup request succeeds.
        """

        key = _created_key(create_url, object_id)
        if key is None:
            return False
        current = self._owned.get(key)
        if current is None:
            return False
        if (
            actor_persona is not None
            and current.get("actor_persona") != actor_persona
        ):
            return False
        del self._owned[key]
        return True

    def is_created_value_owned(
        self,
        create_url: str,
        object_id: Any,
        *,
        actor_persona: Optional[str] = None,
    ) -> bool:
        """Check one exact create response value without URL-shape inference."""

        key = _created_key(create_url, object_id)
        current = self._owned.get(key) if key is not None else None
        if current is None:
            return False
        return (
            actor_persona is None
            or current.get("actor_persona") == actor_persona
        )

    def register_admitted_capture_value(
        self,
        create_url: str,
        object_id: Any,
        *,
        actor_persona: str,
        source_proof_ref: str,
        source_role_binding_ref: str,
        capture_digest: str,
    ) -> Optional[Key]:
        """Register an exact R5 ownership value admitted from this capture.

        This is not a caller-supplied ownership assertion.  The behavioral
        dispatcher may call it only after R5A2 has reconstructed and admitted
        the exact create-to-use lineage for the same persona, proof, role, and
        capture.  Locator proof issuance below retains those bindings.
        """

        if (
            _PERSONA_ID.fullmatch(str(actor_persona or "")) is None
            or _OWNERSHIP_EXPERIMENT_PROOF_REF.fullmatch(
                str(source_proof_ref or "")
            )
            is None
            or _OWNERSHIP_EXPERIMENT_ROLE_REF.fullmatch(
                str(source_role_binding_ref or "")
            )
            is None
            or _CAPTURE_DIGEST.fullmatch(str(capture_digest or "")) is None
        ):
            return None
        key = _created_key(create_url, object_id)
        if key is None:
            return None
        existing = self._owned.get(key)
        if existing is not None:
            return key if existing.get("actor_persona") == actor_persona else None
        self._owned[key] = {
            "actor_persona": actor_persona,
            "collection": key[1],
            "object_id": key[2],
            "proof_source": "admitted_capture_ownership",
            "proof_ref": source_proof_ref,
            "role_binding_ref": source_role_binding_ref,
            "capture_digest": capture_digest,
        }
        return key

    def register_native_witnessed_read(
        self,
        read_url: str,
        witness: NativeOwnedCreationWitness,
        *,
        actor_persona: str,
        destination_ref: str,
    ) -> Optional[Key]:
        """Register a read only after the authenticated native creation seam.

        This does not accept an arbitrary caller boolean. The driver must first
        verify the persona-bound HMAC, and this registry then requires the exact
        active destination reference and actor to match that verified witness.
        """

        if (
            not isinstance(witness, NativeOwnedCreationWitness)
            or witness.persona_id != actor_persona
            or witness.destination_ref != destination_ref
        ):
            return None
        key = _read_key(read_url)
        if key is None:
            return None
        self._owned[key] = {
            "actor_persona": actor_persona,
            "collection": key[1],
            "object_id": key[2],
            "proof_source": "authenticated_native_creation_navigation",
            "proof_ref": witness.proof_ref,
            "create_ref": witness.create_ref,
        }
        return key

    def _locator_matches(
        self,
        *,
        origin: str,
        object_id: str,
        target_owner_persona_id: str,
    ) -> Tuple[Tuple[Key, Dict[str, Any]], ...]:
        return tuple(
            (key, entry)
            for key, entry in self._owned.items()
            if key[0].lower() == origin
            and key[2] == object_id
            and entry.get("actor_persona") == target_owner_persona_id
        )

    def issue_locator_proof(
        self,
        *,
        source_proof_ref: str,
        source_role_binding_ref: str,
        actor_persona_id: str,
        target_owner_persona_id: str,
        method: str,
        url: str,
        body: Any,
        locator_kind: OwnedRequestLocatorKind,
        locator_pointer: str,
    ) -> LocatorOwnershipProof:
        """Seal one exact request only after resolving its value to owned state.

        The caller cannot supply an object ID or collection assertion. Both are
        extracted or resolved inside the registry. Ambiguous same-ID ownership
        across collections fails closed.
        """

        actor = str(actor_persona_id or "").strip()
        owner = str(target_owner_persona_id or "").strip()
        if not actor or not owner or actor == owner:
            raise LocatorOwnershipDenied(
                "locator_ownership_requires_distinct_actor_and_owner"
            )
        object_id = extract_locator_value(
            kind=locator_kind,
            pointer=locator_pointer,
            url=url,
            body=body,
        )
        matches = self._locator_matches(
            origin=request_origin(url),
            object_id=object_id,
            target_owner_persona_id=owner,
        )
        if len(matches) != 1:
            raise LocatorOwnershipDenied(
                "locator_owned_object_is_missing_or_ambiguous"
            )
        key, entry = matches[0]
        if entry.get("proof_source") == "admitted_capture_ownership" and (
            entry.get("proof_ref") != source_proof_ref
            or entry.get("role_binding_ref") != source_role_binding_ref
        ):
            raise LocatorOwnershipDenied(
                "locator_ownership_admitted_capture_binding_mismatch"
            )
        try:
            payload, seal = proof_material(
                self._seal_key,
                registry_ref=self.registry_ref,
                source_proof_ref=source_proof_ref,
                source_role_binding_ref=source_role_binding_ref,
                actor_persona_id=actor,
                target_owner_persona_id=owner,
                method=method,
                url=url,
                body=body,
                object_id=object_id,
                collection=key[1],
                locator_kind=locator_kind,
                locator_pointer=locator_pointer,
            )
            return build_locator_proof(payload, seal)
        except (KeyError, TypeError, ValueError) as exc:
            raise LocatorOwnershipDenied(
                "locator_ownership_source_contract_is_invalid"
            ) from exc

    def verify_locator_proof(
        self,
        proof: LocatorOwnershipProof,
        *,
        actor_persona_id: str,
        target_owner_persona_id: str,
        method: str,
        url: str,
        body: Any,
    ) -> LocatorOwnershipVerification:
        """Verify a sealed proof without consuming budget or granting authority."""

        proof_ref = proof.proof_ref if isinstance(proof, LocatorOwnershipProof) else None
        if not isinstance(proof, LocatorOwnershipProof):
            return LocatorOwnershipVerification(
                False,
                "locator_ownership_proof_is_invalid",
            )
        if proof.registry_ref != self.registry_ref:
            return LocatorOwnershipVerification(
                False,
                "locator_ownership_registry_mismatch",
                proof_ref,
            )
        actor = str(actor_persona_id or "").strip()
        owner = str(target_owner_persona_id or "").strip()
        if not actor or not owner or actor == owner:
            return LocatorOwnershipVerification(
                False,
                "locator_ownership_actor_or_owner_mismatch",
                proof_ref,
            )
        try:
            object_id = extract_locator_value(
                kind=proof.locator_kind,
                pointer=proof.locator_pointer,
                url=url,
                body=body,
            )
            matches = self._locator_matches(
                origin=request_origin(url),
                object_id=object_id,
                target_owner_persona_id=owner,
            )
            if len(matches) != 1:
                return LocatorOwnershipVerification(
                    False,
                    "locator_owned_object_is_missing_or_ambiguous",
                    proof_ref,
                )
            key, _ = matches[0]
            payload, seal = proof_material(
                self._seal_key,
                registry_ref=self.registry_ref,
                source_proof_ref=proof.source_proof_ref,
                source_role_binding_ref=proof.source_role_binding_ref,
                actor_persona_id=actor,
                target_owner_persona_id=owner,
                method=method,
                url=url,
                body=body,
                object_id=object_id,
                collection=key[1],
                locator_kind=proof.locator_kind,
                locator_pointer=proof.locator_pointer,
            )
            expected = build_locator_proof(payload, seal)
        except (KeyError, TypeError, ValueError, LocatorOwnershipDenied) as exc:
            reason = str(exc) if isinstance(exc, LocatorOwnershipDenied) else ""
            if not reason.startswith("locator_ownership_"):
                reason = "locator_ownership_request_drift"
            return LocatorOwnershipVerification(False, reason, proof_ref)
        if expected.to_dict() != proof.to_dict() or not seal_matches(
            self._seal_key,
            proof,
        ):
            return LocatorOwnershipVerification(
                False,
                "locator_ownership_request_or_proof_mismatch",
                proof_ref,
            )
        return LocatorOwnershipVerification(
            True,
            "locator_ownership_verified",
            proof_ref,
        )

    def is_owned(self, read_url: str) -> bool:
        """True iff the object this read targets was researcher-created in this session."""
        key = _read_key(read_url)
        return key is not None and key in self._owned

    def owner_of(self, read_url: str) -> Optional[str]:
        key = _read_key(read_url)
        entry = self._owned.get(key) if key else None
        return entry.get("actor_persona") if entry else None

    def __len__(self) -> int:
        return len(self._owned)
