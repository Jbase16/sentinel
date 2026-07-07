import os
import re
import json

def extract_operations():
    js_dir = "js_bundles"
    operations = {}
    
    # Matches: `query Something(` or `"query Something "` or `mutation Something(`
    pattern = re.compile(r'(query|mutation)\s+([a-zA-Z0-9_]+)\b')
    
    for filename in os.listdir(js_dir):
        if not filename.endswith(".js"):
            continue
            
        filepath = os.path.join(js_dir, filename)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        for match in pattern.finditer(content):
            op_type = match.group(1)
            op_name = match.group(2)
            if op_name not in operations:
                operations[op_name] = []
            
            if filename not in operations[op_name]:
                operations[op_name].append(filename)
                
    print(f"Found {len(operations)} distinct GraphQL operations.")
    with open("js_analysis/operations.json", "w") as f:
        json.dump(operations, f, indent=2)
    print("Saved to js_analysis/operations.json")

if __name__ == "__main__":
    os.makedirs("js_analysis", exist_ok=True)
    extract_operations()
