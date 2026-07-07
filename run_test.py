import asyncio
from core.foundry.driver_native import GhostNativeDriver
import json
from curl_cffi import requests

async def run_cookie_test():
    # 1. Spawn a headless Ghost Native Driver
    print('Connecting to UI...')
    driver = await GhostNativeDriver.launch(headless=True)
    
    # 2. Navigate to whatnot to solve the challenge
    print('Navigating to whatnot...')
    await driver.navigate('https://www.whatnot.com/')
    
    # Wait for challenge to solve
    await asyncio.sleep(10)
    
    # 3. Extract the cookies from the UI's HTTPCookieStore
    cookies = await driver._send('get_cookies')
    print('Harvested cookies:', list(cookies.keys()))
    
    if not cookies:
        print('Failed to harvest cookies.')
        return
        
    # 4. Use curl_cffi to impersonate Safari, injecting the harvested cookies
    print('Testing cf_clearance portability with curl_cffi...')
    # Use safari15_5 which is what Sentinel UI (macOS WebKit) likely most closely resembles
    res = requests.post(
        'https://api.whatnot.com/graphql', 
        headers={'Content-Type': 'application/json'},
        cookies=cookies,
        json={'query': '{ __schema { types { name } } }'},
        impersonate='safari15_5'
    )
    print('Status Code:', res.status_code)
    print(res.text[:500])

asyncio.run(run_cookie_test())
