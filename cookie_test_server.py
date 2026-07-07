import asyncio
import json
import uuid
import os
import signal
import traceback
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
import uvicorn
from curl_cffi import requests

app = FastAPI()

@app.get("/v1/health")
async def health():
    return JSONResponse(content={"status": "ok"})

@app.websocket("/v1/driver/bridge")
async def bridge(websocket: WebSocket):
    await websocket.accept()
    print("UI Connected to test bridge!")
    
    async def send_cmd(cmd, args=None):
        req_id = str(uuid.uuid4())
        payload = {"request_id": req_id, "command": cmd, "args": args or {}}
        await websocket.send_text(json.dumps(payload))
        while True:
            resp = await websocket.receive_text()
            data = json.loads(resp)
            if data.get("request_id") == req_id:
                if "error" in data:
                    raise Exception(f"Command {cmd} failed: {data['error']}")
                return data.get("result")
                
    try:
        print("Launching browser...")
        await send_cmd("launch", {"headless": False})
        
        print("Navigating to whatnot...")
        await send_cmd("navigate", {"url": "https://www.whatnot.com/"})
        
        print("Waiting 15 seconds for challenge to solve...")
        await asyncio.sleep(15)
        
        print("Extracting cookies...")
        cookies = await send_cmd("get_cookies")
        print("Harvested cookies:", list(cookies.keys()))
        
        if not cookies or 'cf_clearance' not in cookies:
            print("WARNING: cf_clearance cookie not found!")
            
        print("Testing cf_clearance portability with curl_cffi...")
        res = requests.post(
            'https://api.whatnot.com/graphql', 
            headers={'Content-Type': 'application/json'},
            cookies=cookies,
            json={'query': '{ __schema { types { name } } }'},
            impersonate='safari15_5'
        )
        print("Status Code:", res.status_code)
        print(res.text[:500])
        
        print("Test complete. Exiting...")
        os.kill(os.getpid(), signal.SIGINT)
        
    except Exception as e:
        print(f"Error occurred:")
        traceback.print_exc()
        os.kill(os.getpid(), signal.SIGINT)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
