"""
Safe evaluator for CAL expressions.

This module defines a tiny, explicit expression language:
  - Boolean ops: and, or, not
  - Comparisons: == != < <= > >= in not in
  - Names: context, tool
  - Constants: strings, ints, floats, bools, None
  - Attribute access (limited depth, no private attrs)
  - Numeric addition/subtraction (for simple counters)

Everything else is rejected.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, Iterable


class UnsafeExpression(Exception):
    pass


ALLOWED_ROOT_NAMES = {"context", "tool"}
ALLOWED_BOOL_OPS = (ast.And, ast.Or)
ALLOWED_UNARY_OPS = (ast.Not,)
ALLOWED_CMP_OPS = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
)
ALLOWED_BIN_OPS = (ast.Add, ast.Sub)

MAX_ATTR_DEPTH = 3

# Supported value types in the evaluation context
SAFE_VALUE_TYPES = (str, int, float, bool, type(None))
SAFE_COLLECTION_TYPES = (list, tuple, set, frozenset)


class _SafeObject:
    """Safe dot-access wrapper around a dict."""

    __slots__ = ("_data",)

    _DEFAULTS = {
        "resource_cost": 0,
        "active_tools": 0,
        "max_concurrent": 0,
        "gates": (),
        "tags": (),
        "knowledge": {},
    }

    def __init__(self, data: Dict[str, Any]):
        if not isinstance(data, dict):
            raise UnsafeExpression("Context/tool must be dict-like")
        self._data = data

    @classmethod
    def from_value(cls, value: Any) -> "_SafeObject":
        if isinstance(value, _SafeObject):
            return value
        if hasattr(value, "_data") and isinstance(getattr(value, "_data"), dict):
            return cls(getattr(value, "_data"))
        if isinstance(value, dict):
            return cls(value)
        raise UnsafeExpression("Context/tool must be dict-like")

    def get_attr(self, key: str) -> Any:
        if key.startswith("_"):
            raise UnsafeExpression("Private attributes are not allowed")
        if key in self._DEFAULTS and key not in self._data:
            return self._coerce_value(self._DEFAULTS[key])
        return self._coerce_value(self._data.get(key))

    def _coerce_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return _SafeObject(value)
        if isinstance(value, SAFE_COLLECTION_TYPES):
            # Return tuple to prevent mutation and preserve truthiness
            return tuple(value)
        if isinstance(value, SAFE_VALUE_TYPES):
            return value
        if value is None:
            return None
        raise UnsafeExpression("Unsafe value type in context/tool")


class _CALExpressionValidator(ast.NodeVisitor):
    def visit(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Load):
            return None
        if isinstance(node, ast.Expression):
            return self.visit(node.body)
        return super().visit(node)

    def generic_visit(self, node: ast.AST) -> Any:
        allowed = (
            ast.BoolOp,
            ast.UnaryOp,
            ast.BinOp,
            ast.Compare,
            ast.Name,
            ast.Attribute,
            ast.Constant,
        )
        if not isinstance(node, allowed):
            raise UnsafeExpression(f"Disallowed syntax: {type(node).__name__}")
        return super().generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        raise UnsafeExpression("Function calls are not allowed")

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        raise UnsafeExpression("Subscript access is not allowed")

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        raise UnsafeExpression("Lambda expressions are not allowed")

    def visit_Name(self, node: ast.Name) -> Any:
        if node.id not in ALLOWED_ROOT_NAMES:
            raise UnsafeExpression(f"Unknown name: {node.id}")

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        depth = 0
        cur = node
        while isinstance(cur, ast.Attribute):
            if cur.attr.startswith("_"):
                raise UnsafeExpression("Private attributes are not allowed")
            depth += 1
            cur = cur.value
        if depth > MAX_ATTR_DEPTH:
            raise UnsafeExpression("Attribute access too deep")
        if not isinstance(cur, ast.Name):
            raise UnsafeExpression("Attribute root must be a name")
        if cur.id not in ALLOWED_ROOT_NAMES:
            raise UnsafeExpression(f"Unknown name: {cur.id}")
        # Continue visiting to validate nested nodes
        return self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> Any:
        if not isinstance(node.op, ALLOWED_BOOL_OPS):
            raise UnsafeExpression("Disallowed boolean operator")
        for value in node.values:
            self.visit(value)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
        if not isinstance(node.op, ALLOWED_UNARY_OPS):
            raise UnsafeExpression("Disallowed unary operator")
        self.visit(node.operand)

    def visit_BinOp(self, node: ast.BinOp) -> Any:
        if not isinstance(node.op, ALLOWED_BIN_OPS):
            raise UnsafeExpression("Disallowed binary operator")
        self.visit(node.left)
        self.visit(node.right)

    def visit_Compare(self, node: ast.Compare) -> Any:
        for op in node.ops:
            if not isinstance(op, ALLOWED_CMP_OPS):
                raise UnsafeExpression("Disallowed comparison operator")
        self.visit(node.left)
        for comp in node.comparators:
            self.visit(comp)


def validate_expression(expr: str) -> None:
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpression(f"Invalid syntax: {e}") from e
    _CALExpressionValidator().visit(tree)


def safe_eval(expr: str, context: Any, tool: Any) -> bool:
    validate_expression(expr)
    scope = {
        "context": _SafeObject.from_value(context),
        "tool": _SafeObject.from_value(tool),
    }
    tree = ast.parse(expr, mode="eval")
    return bool(_eval_node(tree.body, scope))


def _eval_node(node: ast.AST, scope: Dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        return scope[node.id]

    if isinstance(node, ast.Attribute):
        base = _eval_node(node.value, scope)
        if not isinstance(base, _SafeObject):
            raise UnsafeExpression("Attribute access on unsafe object")
        return base.get_attr(node.attr)

    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            for v in node.values:
                if not _eval_node(v, scope):
                    return False
            return True
        if isinstance(node.op, ast.Or):
            for v in node.values:
                if _eval_node(v, scope):
                    return True
            return False

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, scope)

    if isinstance(node, ast.BinOp):
        left = _eval_node(node.left, scope)
        right = _eval_node(node.right, scope)
        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            raise UnsafeExpression("Binary ops only allowed on numbers")
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right

    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, scope)
        for op, right_node in zip(node.ops, node.comparators):
            right = _eval_node(right_node, scope)
            if isinstance(op, ast.Eq) and not (left == right):
                return False
            if isinstance(op, ast.NotEq) and not (left != right):
                return False
            if isinstance(op, ast.In) and not (left in right):
                return False
            if isinstance(op, ast.NotIn) and not (left not in right):
                return False
            if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                if _both_collections(left, right):
                    if not _compare_collections(left, right, op):
                        return False
                else:
                    if isinstance(op, ast.Lt) and not (left < right):
                        return False
                    if isinstance(op, ast.LtE) and not (left <= right):
                        return False
                    if isinstance(op, ast.Gt) and not (left > right):
                        return False
                    if isinstance(op, ast.GtE) and not (left >= right):
                        return False
            left = right
        return True

    raise UnsafeExpression(f"Unhandled AST node: {type(node).__name__}")


def _both_collections(left: Any, right: Any) -> bool:
    return isinstance(left, SAFE_COLLECTION_TYPES) and isinstance(right, SAFE_COLLECTION_TYPES)


def _compare_collections(left: Iterable[Any], right: Iterable[Any], op: ast.cmpop) -> bool:
    try:
        left_set = set(left)
        right_set = set(right)
    except TypeError as e:
        raise UnsafeExpression("Unhashable elements in collection comparison") from e

    if isinstance(op, ast.Lt):
        return left_set < right_set
    if isinstance(op, ast.LtE):
        return left_set <= right_set
    if isinstance(op, ast.Gt):
        return left_set > right_set
    if isinstance(op, ast.GtE):
        return left_set >= right_set
    return False
