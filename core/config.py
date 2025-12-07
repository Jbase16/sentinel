# core/config.py

import os

# AI Configuration
AI_PROVIDER = os.getenv("ARAULTRA_AI_PROVIDER", "ollama")  # "ollama" or "openai"
OLLAMA_URL = os.getenv("ARAULTRA_OLLAMA_URL", "http://localhost:11434")
# Default to llama3:latest as it's a good balance, but allow override
AI_MODEL = os.getenv("ARAULTRA_AI_MODEL", "llama3:latest") 

# Fallback to regex if AI fails?
AI_FALLBACK_ENABLED = True
