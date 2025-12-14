from ..tool_base import ToolBase

class NmapScan(ToolBase):
    def __init__(self):
        super().__init__("nmap")

    def scan_basic(self, target: str):
        command = f"nmap -sV -T4 {target}"
        return self.run(command, metadata={"target": target, "type": "basic_scan"})