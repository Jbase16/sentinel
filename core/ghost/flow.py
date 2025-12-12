"""
core/ghost/flow.py
The Session & Flow Tracker.
"Ghost observes the user to learn the rules before breaking them."
"""

from typing import List, Dict, Any, Optional
import uuid
import time

class FlowStep:
    def __init__(self, method: str, url: str, params: Dict, headers: Dict):
        self.id = str(uuid.uuid4())
        self.method = method
        self.url = url
        self.params = params
        self.headers = headers
        self.timestamp = time.time()
        self.response_status = 0

class UserFlow:
    """
    Represents a sequence of actions (e.g., Login -> Search -> AddToCart).
    Ghost uses this to understand STATE.
    """
    def __init__(self, name: str):
        self.name = name
        self.steps: List[FlowStep] = []
        self.auth_tokens: Dict[str, str] = {} # Extracted tokens

    def add_step(self, step: FlowStep):
        self.steps.append(step)

    def extract_tokens(self, headers: Dict):
        # Heuristic: Find Bearer/Cookie
        for k, v in headers.items():
            if k.lower() in ["authorization", "cookie", "x-csrf-token"]:
                self.auth_tokens[k] = v

class FlowMapper:
    """
    Records and replays flows.
    """
    _instance = None
    
    @staticmethod
    def instance():
        if FlowMapper._instance is None:
            FlowMapper._instance = FlowMapper()
        return FlowMapper._instance

    def __init__(self):
        self.active_flows: Dict[str, UserFlow] = {}

    def start_recording(self, flow_name: str) -> str:
        fid = str(uuid.uuid4())
        self.active_flows[fid] = UserFlow(flow_name)
        return fid

    def record_request(self, flow_id: str, method, url, params, headers):
        if flow_id in self.active_flows:
            step = FlowStep(method, url, params, headers)
            self.active_flows[flow_id].add_step(step)
            # Auto-learn tokens
            self.active_flows[flow_id].extract_tokens(headers)
