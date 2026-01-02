"""
CAL Parser (core/cal/parser.py)

PURPOSE:
Parses the Collaborative Agent Logic (CAL) DSL into executable policy objects.

SYNTAX:
Law <Name> {
    Claim: "<String>"
    When: <Expression>
    And:  <Expression>
    Then: <Action> "<Reason>"
}
"""

import re
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class Condition:
    raw_expression: str

    def evaluate(self, context: Any, tool: Dict) -> bool:
        """
        Evaluate the condition against the context.
        Security Note: Uses restricted eval or simple parsing.
        For V1, we will implement a safe sub-set evaluator.
        """
        # Simplistic Safe Eval for V1:
        # Replace 'context.x' with local var access
        # This is a placeholder for a robust AST walker later.
        
        # Mapping for eval scope
        # Wrap BOTH context and tool to support dot notation (context.x, tool.phase)
        safe_scope = {
            "context": _DictWrapper(context) if isinstance(context, dict) else context,
            "tool": _DictWrapper(tool) if isinstance(tool, dict) else tool
        }
        
        # Operators map for custom CAL syntax "IS NOT EMPTY" etc.
        expr = self.raw_expression
        expr = expr.replace("IS NOT EMPTY", "!= []").replace("IS EMPTY", "== []")
        expr = expr.replace("NOT IN", "not in") # Pythonic
        # 'IN' is already pythonic
        
        try:
            # DANGEROUS: eval() usage. 
            # Mitigation: In a real production system, we'd build an AST visitor.
            # For this prototype agent, we trust the internal Constitution.
            return bool(eval(expr, {"__builtins__": {}}, safe_scope))
        except Exception as e:
            logger.error(f"[CAL] Eval failed for '{expr}': {e}")
            return False

class _DictWrapper:
    """Helper to allow dot notation for dicts (tool.phase instead of tool['phase'])."""
    def __init__(self, data):
        self._data = data
    def __getattr__(self, item):
        val = self._data.get(item)
        if isinstance(val, dict):
            return _DictWrapper(val)
        return val

@dataclass
class Action:
    verb: str # ALLOW, DENY
    reason_template: str

@dataclass
class Law:
    name: str
    claim: str
    conditions: List[Condition] = field(default_factory=list)
    action: Optional[Action] = None

class CALParser:
    def parse_file(self, path: str) -> List[Law]:
        with open(path, "r") as f:
            content = f.read()
        return self.parse_string(content)

    def parse_string(self, content: str) -> List[Law]:
        laws = []
        current_law = None
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Match: Law Name {
            m_law_start = re.match(r"Law\s+(\w+)\s*\{", line)
            if m_law_start:
                current_law = Law(name=m_law_start.group(1), claim="")
                continue
                
            # Match: }
            if line == "}":
                if current_law:
                    laws.append(current_law)
                    current_law = None
                continue
            
            if not current_law:
                continue
                
            # Directives
            if line.startswith("Claim:"):
                current_law.claim = line.split(":", 1)[1].strip().strip('"')
            elif line.startswith("When:"):
                expr = line.split(":", 1)[1].strip()
                current_law.conditions.append(Condition(expr))
            elif line.startswith("And:"):
                expr = line.split(":", 1)[1].strip()
                current_law.conditions.append(Condition(expr))
            elif line.startswith("Then:"):
                parts = line.split(":", 1)[1].strip().split(" ", 1)
                verb = parts[0]
                reason = parts[1].strip('"') if len(parts) > 1 else ""
                current_law.action = Action(verb, reason)

        return laws
