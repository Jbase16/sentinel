#!/usr/bin/env python3
"""
start_sentinel_brain.py
Serves the fine-tuned Sentinel-9B (Gemma 2 9B + Surgical Adapter) via Ollama-compatible API.
"""

import logging
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import os

# 🧠 CONFIGURATION
# Resolve paths relative to the project root
# Script is in scripts/, so root is one level up
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODELS_DIR, "gemma-2-9b-it-sft-fused-4bit")
ADAPTER_PATH = os.path.join(MODELS_DIR, "surgical_adapter")
PORT = 8009

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SentinelBrain")

# Lazy load to allow script to be imported without MLX
model = None
tokenizer = None

def ensure_model_loaded():
    global model, tokenizer
    if model is None:
        import mlx.core as mx
        from mlx_lm import load
        print("🧠 Initializing Sentinel-9B Neural Core...")
        model, tokenizer = load(MODEL_PATH, adapter_path=ADAPTER_PATH)
        print("✅ Model Loaded. Surgical Adapter Active.")

class SentinelHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging, use our logger instead
        pass
    
    def do_GET(self):
        if self.path == "/api/tags":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {"models": [{"name": "sentinel-9b-god-tier"}]}
            self.wfile.write(json.dumps(response).encode())
        elif self.path == "/health" or self.path == "/":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "model": "sentinel-9b-god-tier"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/generate":
            ensure_model_loaded()
            from mlx_lm import generate
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data)
                prompt = data.get("prompt", "")
                system = data.get("system", "")
                
                # Combine System + User into Gemma Format
                full_prompt = f"<start_of_turn>user\n{system}\n\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
                
                logger.info(f"Thinking on prompt (len={len(full_prompt)})...")
                
                # Generate
                start = time.time()
                response = generate(model, tokenizer, prompt=full_prompt, max_tokens=2048, verbose=False)
                taken = time.time() - start
                
                result = {"response": response, "done": True, "total_duration": int(taken*1e9)}
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
                logger.info(f"Response sent ({len(response)} chars) in {taken:.2f}s")
                
            except Exception as e:
                logger.error(f"Error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=SentinelHandler, port=PORT):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logger.info(f"🚀 Sentinel Brain active at http://localhost:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
