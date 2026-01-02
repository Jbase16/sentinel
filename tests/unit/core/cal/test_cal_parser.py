
import pytest
from core.cal.parser import CALParser, Law, Action
from pathlib import Path

def test_parser_basic_string():
    cal_content = """
    Law TestLaw {
        Claim: "This is a test"
        When: 1 == 1
        And:  2 > 1
        Then: ALLOW "Math works"
    }
    """
    parser = CALParser()
    laws = parser.parse_string(cal_content)
    
    assert len(laws) == 1
    law = laws[0]
    assert law.name == "TestLaw"
    assert law.claim == "This is a test"
    assert len(law.conditions) == 2
    assert law.action.verb == "ALLOW"
    assert law.action.reason_template == "Math works"

def test_parser_constitution_file():
    # Verify the actual asset file
    constitution_path = Path("assets/laws/constitution.cal")
    if not constitution_path.exists():
        pytest.skip("Constitution file not created yet")
        
    parser = CALParser()
    laws = parser.parse_file(str(constitution_path))
    
    # We expect at least the 3 laws we wrote
    assert len(laws) >= 3
    names = [l.name for l in laws]
    assert "PassiveBeforeActive" in names
    assert "EvidenceGates" in names
    assert "ResourceAwareness" in names

def test_condition_eval():
    from core.cal.parser import Condition
    
    # Test safe eval context wrapper
    context = {"x": 10}
    tool = {"phase": 2}
    
    c = Condition("context.x == 10")
    assert c.evaluate(context, tool) is True
    
    c2 = Condition("tool.phase > 1")
    assert c2.evaluate(context, tool) is True
    
    # Test replacement
    c3 = Condition("tool.phase IS NOT EMPTY") # should become != []
    # But evaluating "2 != []" is True in Python. 
    # Let's test a list.
    tool_list = {"tags": []}
    c_list = Condition("tool.tags IS EMPTY")
    assert c_list.evaluate(context, tool_list) is True
