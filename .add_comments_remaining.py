#!/usr/bin/env python3
"""
Batch adds educational header comments to remaining SentinelForge files.
"""

import os
from pathlib import Path

# File-specific header documentation
HEADERS = {
    # === Data Store Files ===
    "core/data/findings_store.py": """# ============================================================================
# core/data/findings_store.py
# Findings Store - In-Memory + Persistent Vulnerability Storage
""",
    
    "core/data/issues_store.py": """# ============================================================================
# core/data/issues_store.py
# Issues Store - Confirmed Exploitable Vulnerability Storage
""",

    "core/data/evidence_store.py": """# ============================================================================
# core/data/evidence_store.py  
# Evidence Store - File-Based Artifact Preservation
""",

    "core/data/killchain_store.py": """# ============================================================================
# core/data/killchain_store.py
# Kill Chain Store - Attack Progression Tracking
""",
}

def add_header_to_file(filepath: Path, header: str):
    """Add educational header to a file if it doesn't have comprehensive comments."""
    try:
        content = filepath.read_text()
        
        # Skip if already has substantial header (heuristic: starts with ===== line)
        if content.startswith("#" + "=" * 70):
            print(f"⏭  Skipping {filepath} (already has header)")
            return
            
        # Prepend header
        new_content = header + content
        filepath.write_text(new_content)
        print(f"✅ Added header to {filepath}")
        
    except Exception as e:
        print(f"❌ Error processing {filepath}: {e}")

def main():
    """Process all configured files."""
    base_dir = Path("/Users/jason/Developer/sentinelforge")
    
    for rel_path, header in HEADERS.items():
        filepath = base_dir / rel_path
        if filepath.exists():
            add_header_to_file(filepath, header)
        else:
            print(f"⚠️  File not found: {filepath}")
    
    print("\n✨ Header annotation complete!")

if __name__ == "__main__":
    main()
