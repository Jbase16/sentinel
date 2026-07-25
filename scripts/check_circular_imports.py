
import os
import sys
import importlib
import pkgutil
import traceback

# Add project root to path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

def check_imports(start_dir):
    """Recursively import all modules in start_dir to catch circular dependency errors."""
    print(f"Checking for circular imports in {start_dir}...")
    errors = []
    
    # Walk through logical packages using pkgutil
    # This prevents us from importing random .py files that aren't modules
    # But for a backend app, simple file walking might be safer execution-wise
    # unless we actually want to trigger the import logic.
    # We DO want to trigger import logic.
    
    visited = set()
    
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.endswith(".py") and file != "__init__.py":
                # Construct module path
                rel_path = os.path.relpath(os.path.join(root, file), PROJECT_ROOT)
                module_name = rel_path.replace(os.path.sep, ".").replace(".py", "")
                
                if module_name in visited:
                    continue
                
                try:
                    importlib.import_module(module_name)
                    # print(f"✅ {module_name}")
                    visited.add(module_name)
                except ImportError as e:
                    # Ignore optional dependency errors if not installed
                    if "No module named" in str(e) and "core" not in str(e):
                        continue
                        
                    msg = f"❌ Error importing {module_name}: {e}"
                    print(msg)
                    errors.append(msg)
                    # traceback.print_exc()
                except Exception as e:
                    msg = f"❌ Exception importing {module_name}: {e}"
                    print(msg)
                    errors.append(msg)
                    
    return len(errors), errors

if __name__ == "__main__":
    target_dir = os.path.join(PROJECT_ROOT, "core")
    count, errs = check_imports(target_dir)
    
    if count > 0:
        print(f"\nFound {count} import errors (likely circular deps or missing env):")
        for e in errs:
            print(e)
        sys.exit(1)
    else:
        print("\n✅ No circular import crash loops detected.")
        sys.exit(0)
