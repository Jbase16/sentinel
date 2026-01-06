
import json
import os
import sys
from pathlib import Path

# Add repo root to path
sys.path.append(str(Path(__file__).resolve().parents[3]))

try:
    from core.server.api import app
    from core.base.config import get_config
    
    # Ensure config is loaded
    config = get_config()
    
    print(f"Generating OpenAPI spec for {app.title} v{app.version}...")
    
    openapi_schema = app.openapi()
    
    output_path = Path("openapi.json")
    with open(output_path, "w") as f:
        json.dump(openapi_schema, f, indent=2)
        
    print(f"✅ OpenAPI spec saved to {output_path.absolute()}")
    
except Exception as e:
    print(f"❌ Failed to generate OpenAPI spec: {e}")
    sys.exit(1)
