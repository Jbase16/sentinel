
import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

print("Attempting to import core.base.config...")
try:
    from core.base.config import AI_PROVIDER, OLLAMA_URL
    print(f"Success: AI_PROVIDER={AI_PROVIDER}, OLLAMA_URL={OLLAMA_URL}")
except Exception as e:
    print(f"Failed to import config: {e}")
    sys.exit(1)

print("\nAttempting to import core.ai.provider (if it exists)...")
try:
    from core.base.config import AIProvider
    print(f"Success: AIProvider imported. Enum members: {list(AIProvider)}")
except ImportError:
    print("AIProvider not found in core.ai.provider")
except Exception as e:
    print(f"Failed to import AIProvider: {e}")
