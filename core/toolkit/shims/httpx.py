from ..tool_base import ToolBase

class Httpx(ToolBase):
    def __init__(self):
        super().__init__("httpx")

    def probe(self, input_file: str):
        command = f"httpx -silent -l {input_file}"
        return self.run(command, metadata={"input_file": input_file, "type": "http_probe"})