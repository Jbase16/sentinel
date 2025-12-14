import shutil
import os

TOOLS = ["nmap", "httpx", "subfinder", "ollama"]

print("--- Checking Tool Availability ---")
for tool in TOOLS:
    path = shutil.which(tool)
    if path:
        print(f"[OK] {tool}: {path}")
    else:
        print(f"[MISSING] {tool}")

print("\n--- Checking PATH ---")
print(os.environ.get("PATH"))

