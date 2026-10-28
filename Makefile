.PHONY: schemas check-schemas
PYTHON ?= python3

schemas:
	@echo "Generating web schemas..."
	$(PYTHON) scripts/generate_web_schemas.py

check-schemas:
	@echo "Checking schema drift..."
	$(PYTHON) scripts/check_schema_drift.py
