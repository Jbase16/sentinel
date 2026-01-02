"""
Verification Script for Project MIMIC (Model Inferencer).
Scenario:
1. Feed complex JSON payload (User Profile).
2. Expect correct APISchema structure.
"""
from core.sentient.mimic.model_inferencer import ModelInferencer
from core.sentient.mimic.types import DataType

def run_test():
    print("🧠 Initializing Model Inferencer...")
    
    # 1. Simple Object
    payload = {
        "id": 123,
        "name": "Alice",
        "is_admin": False
    }
    
    print(f"   Fed: {payload}")
    schema = ModelInferencer.infer(payload)
    
    assert schema.type == DataType.OBJECT
    assert schema.properties["id"].type == DataType.INTEGER
    assert schema.properties["name"].type == DataType.STRING
    assert schema.properties["is_admin"].type == DataType.BOOLEAN
    
    print("✅ Simple Object Inference Verified")
    
    # 2. Nested Object + Array
    payload_complex = {
        "user": {
            "id": 1,
            "roles": ["admin", "editor"],
            "settings": {
                "theme": "dark"
            }
        }
    }
    
    print(f"   Fed: {payload_complex}")
    schema_c = ModelInferencer.infer(payload_complex)
    
    user_prop = schema_c.properties["user"]
    assert user_prop.type == DataType.OBJECT
    assert user_prop.properties["roles"].type == DataType.ARRAY
    assert user_prop.properties["roles"].items.type == DataType.STRING
    assert user_prop.properties["settings"].properties["theme"].type == DataType.STRING
    
    print("✅ Complex/Nested Inference Verified")
    print("\n🎉 MIMIC Inferencer Verified!")

if __name__ == "__main__":
    run_test()
