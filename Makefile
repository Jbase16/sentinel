.PHONY: schemas check-schemas

schemas:
	@echo "Generating web schemas..."
	python scripts/generate_web_schemas.py

check-schemas:
	@echo "Checking schema drift..."
	python scripts/check_schema_drift.py
