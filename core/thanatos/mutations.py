"""
core/thanatos/mutations.py

Purpose:
    Defines the atomic "Operators" that Thanatos uses to break things.
    Each operator is a specific strategy for violating a contract.

Magnum Opus Standards:
    - Determinism: Operators must be reproducible.
    - Isolation: Operators shouldn't depend on global state.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from .models import MutationOpType

@dataclass(frozen=True)
class Mutation:
    """
    A specific application of an operator.
    """
    op: MutationOpType
    params: Dict[str, Any]
    description: str

class MutationOperator(ABC):
    @abstractmethod
    def generate(self, context: Dict[str, Any]) -> List[Mutation]:
        """
        Produce a list of mutations based on the target context.
        Context usually contains: 'params', 'body_schema', 'headers'.
        """
        pass

class TypeJuggling(MutationOperator):
    def generate(self, context: Dict[str, Any]) -> List[Mutation]:
        mutations = []
        # Primitive type swaps for JSON body fields
        schema = context.get("body_schema", {})
        for field, expected_type in schema.items():
            if expected_type == "int":
                mutations.append(Mutation(
                    op=MutationOpType.TYPE_JUGGLING,
                    params={"field": field, "value": "not_an_int"},
                    description=f"Send string instead of int for {field}"
                ))
            elif expected_type == "string":
                mutations.append(Mutation(
                    op=MutationOpType.TYPE_JUGGLING,
                    params={"field": field, "value": 12345},
                    description=f"Send int instead of string for {field}"
                ))
        return mutations

class BoundaryViolation(MutationOperator):
    def generate(self, context: Dict[str, Any]) -> List[Mutation]:
        mutations = []
        # Check params/body for numeric fields
        schema = context.get("body_schema", {})
        for field, expected_type in schema.items():
            if expected_type == "int":
                mutations.append(Mutation(
                    op=MutationOpType.BOUNDARY_VIOLATION,
                    params={"field": field, "value": -1},
                    description=f"Negative value for {field}"
                ))
                mutations.append(Mutation(
                    op=MutationOpType.BOUNDARY_VIOLATION,
                    params={"field": field, "value": 2147483648}, # MaxInt32 + 1
                    description=f"Overflow value for {field}"
                ))
        return mutations

class AuthConfusion(MutationOperator):
    def generate(self, context: Dict[str, Any]) -> List[Mutation]:
        return [
            Mutation(
                op=MutationOpType.AUTH_CONFUSION,
                params={"action": "drop_header", "header": "Authorization"},
                description="Drop Authorization header"
            ),
            Mutation(
                op=MutationOpType.AUTH_CONFUSION,
                params={"action": "corrupt_token"},
                description="Send malformed Bearer token"
            )
        ]

class UnicodeStorm(MutationOperator):
    ZALGO = "H̗u̠m̖a͕n̗s ̘h̶a̠v̵e ̜f̶o̺r̼g̪o͚țt̞e̠n"
    EMOJI = "🦄🛑💣" * 10
    
    def generate(self, context: Dict[str, Any]) -> List[Mutation]:
        mutations = []
        schema = context.get("body_schema", {})
        for field, expected_type in schema.items():
            if expected_type == "string":
                mutations.append(Mutation(
                    op=MutationOpType.UNICODE_STORM,
                    params={"field": field, "value": self.ZALGO},
                    description=f"Zalgo injection in {field}"
                ))
                mutations.append(Mutation(
                    op=MutationOpType.UNICODE_STORM,
                    params={"field": field, "value": self.EMOJI},
                    description=f"Emoji overflow in {field}"
                ))
        return mutations

class MutationLibrary:
    """
    Registry of all available mutation operators.
    """
    def __init__(self):
        self.operators: List[MutationOperator] = [
            TypeJuggling(),
            BoundaryViolation(),
            AuthConfusion(),
            UnicodeStorm()
        ]

    def generate_all(self, context: Dict[str, Any]) -> List[Mutation]:
        all_mutations = []
        for op in self.operators:
            all_mutations.extend(op.generate(context))
        return all_mutations
