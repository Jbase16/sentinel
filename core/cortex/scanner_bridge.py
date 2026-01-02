
from typing import List, Dict, Any, Optional
from core.toolkit.raw_classifier import classify
from core.cal.types import Evidence, Provenance
from core.cal.engine import ReasoningSession
import logging

logger = logging.getLogger(__name__)

class ScannerBridge:
    """
    Bridge between the Scanner Engine (which runs tools) and the Cortex/Classifier
    (which normalizes output into structured findings).
    
    This adapter decrypts the boundary between the execution layer (Engine)
    and the intelligence layer (Cortex).
    """

    @staticmethod
    def classify(tool: str, target: str, output: str) -> List[Dict[str, Any]]:
        """
        Classifies raw tool output into normalized findings.
        
        Args:
            tool: Name of the tool (e.g., 'nmap', 'httpx')
            target: The target scan argument
            output: The raw stdout from the tool
            
        Returns:
            List of findings as dictionaries.
        """
        return classify(tool, target, output)

    @staticmethod
    def emit_evidence(session_id: str, tool: str, target: str, output: str) -> Evidence:
        """
        [CAL INTEGRATION]
        Converts raw tool output into an Evidence primitive.
        
        This allows the Argumentation Engine to use this output to support
        or dispute claims.
        """
        # Create Evidence Object
        evidence = Evidence(
            content={"raw_output": output},
            description=f"Output from {tool} scan on {target}",
            provenance=Provenance(
                source=f"Scanner:{tool}",
                method="automated",
                run_id=session_id
            ),
            confidence=1.0 # The tool output itself is a fact
        )
        
        # In a real integration, we'd attach this to the persistent session
        # session = ReasoningSession.get(session_id)
        # session.add_evidence(evidence)
        
        logger.debug(f"[ScannerBridge] Created Evidence {evidence.id} from {tool}")
        return evidence
