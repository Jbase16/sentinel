"""
Verifies that the SentinelForge project structure is still clean and consistent.
"""

import os

ALLOWED_ROOT = {"sentinelforge", "README.md",
                "requirements.txt", "tests", "ui", "docs", "tools"}

def main():
    for item in os.listdir("."):
        if item not in ALLOWED_ROOT:
            print(f"⚠️  Unexpected item at project root: {item}")

if __name__ == "__main__":
    main()
