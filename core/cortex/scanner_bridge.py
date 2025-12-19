
from typing import List, Dict, Any
from core.toolkit.raw_classifier import classify

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
