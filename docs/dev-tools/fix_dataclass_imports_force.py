#!/usr/bin/env python3


#!/usr/bin/env python3
"""
Automatically inserts 'from dataclasses import dataclass'
in any Python file under ./core that uses @dataclass but
forgot to import it.
"""

import os
import re

ROOT = "core"
IMPORT_LINE = "from dataclasses import dataclass\n"

def needs_fix(content: str) -> bool:
    needs_dataclass = "@dataclass" in content and "from dataclasses import dataclass" not in content
    
    # Check if field is used but not imported
    has_field_usage = "= field(" in content
    # Simple check: does the file contain "from dataclasses import ... field" or ", field"
    # This is heuristic but better than checking global "field" existence
    is_field_imported = "from dataclasses import" in content and (", field" in content or " import field" in content)
    
    needs_field = has_field_usage and not is_field_imported
    
    return needs_dataclass or needs_field

def find_insert_index(lines):
    """Find first line after imports/comments/docstrings."""
    for i, line in enumerate(lines):
        stripped = line.strip()
        # skip empty lines, comments, or module docstrings
        if (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith('"""')
            or stripped.startswith("'''")
            or stripped.startswith("import ")
            or stripped.startswith("from ")
        ):
            continue
        return i
    return 0

def patch_file(path):
    with open(path, "r") as f:
        lines = f.readlines()

    # Find where to insert or check existing imports
    try:
        idx = [i for i, l in enumerate(lines) if "from dataclasses import dataclass" in l][0]
        # It exists, check if we need to add field
        if "field" not in lines[idx] and "= field(" in "".join(lines):
             lines[idx] = lines[idx].replace("from dataclasses import dataclass", "from dataclasses import dataclass, field")
    except IndexError:
        # Import not found, insert it
        idx = find_insert_index(lines)
        new_import = "from dataclasses import dataclass"
        if "= field(" in "".join(lines):
            new_import += ", field"
        lines.insert(idx, new_import + "\n")

    with open(path, "w") as f:
        f.writelines(lines)
    print(f"✅ Added dataclass import → {path}")
    return True

def main():
    modified = 0
    for root, _, files in os.walk(ROOT):
        for file in files:
            if not file.endswith(".py"):
                continue
            path = os.path.join(root, file)
            with open(path, "r") as f:
                content = f.read()
            if needs_fix(content):
                if patch_file(path):
                    modified += 1
    if modified == 0:
        print("✨ All dataclass imports already present or no files needed changes.")

if __name__ == "__main__":
    main()
