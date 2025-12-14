from ..tool_base import ToolBase

class Subfinder(ToolBase):
    def __init__(self):
        super().__init__("subfinder")

    def enumerate(self, domain: str):
        command = f"subfinder -silent -d {domain}"
        return self.run(command, metadata={"domain": domain, "type": "subdomain_enum"})