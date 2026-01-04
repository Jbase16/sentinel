
import os
import sys
import importlib
import pkgutil
import traceback

# Add project root
sys.path.append(os.getcwd())

def check_imports(package_name="core"):
    """
    Recursively import all modules in the package to check for circularity/errors.
    """
    print(f"Checking imports for package: {package_name}...")
    success_count = 0
    error_count = 0
    
    try:
        package = importlib.import_module(package_name)
    except Exception as e:
        print(f"CRITICAL: Failed to import root package {package_name}: {e}")
        return

    # Walk through all modules
    for importer, modname, ispkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        try:
            # print(f"  Importing {modname}...", end="")
            importlib.import_module(modname)
            # print(" OK")
            success_count += 1
        except Exception as e:
            print(f"\nFAIL: {modname}\n{traceback.format_exc()}")
            error_count += 1

    print(f"\n--- Import Check Results ---")
    print(f"Modules Verified: {success_count}")
    print(f"Import Failures: {error_count}")
    
    if error_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    check_imports()
