import pytest

from core.cal.safe_eval import safe_eval, UnsafeExpression


BAD_EXPRESSIONS = [
    "().__class__",
    "__import__('os')",
    "(lambda x: x)(1)",
    "[x for x in [1]]",
    "a.__dict__",
    "a['key']",
]


def test_breakout_payloads_are_rejected():
    for expr in BAD_EXPRESSIONS:
        with pytest.raises(UnsafeExpression):
            safe_eval(expr, {"a": {}}, {"b": {}})
