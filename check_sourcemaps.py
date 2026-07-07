import asyncio
import re
from core.net.http_factory import create_async_client

async def check_sourcemaps():
    client = create_async_client(high_evasion=True)
    try:
        print("Fetching https://www.whatnot.com/ ...")
        res = await client.get('https://www.whatnot.com/')
        if res.status_code != 200:
            print(f"Failed to fetch main page: {res.status_code}")
            return
            
        js_urls = re.findall(r'src="([^"]+\.js)"', res.text)
        # Also look for modulepreload or other links just in case
        js_urls += re.findall(r'href="([^"]+\.js)"', res.text)
        js_urls = list(set(js_urls))
        
        print(f"Found {len(js_urls)} unique JS bundles. Checking for sourcemaps...")
        
        found = False
        for js_url in js_urls:
            if js_url.startswith('/'):
                full_url = f"https://www.whatnot.com{js_url}"
            elif js_url.startswith('http'):
                full_url = js_url
            else:
                full_url = f"https://www.whatnot.com/{js_url}"
                
            map_url = full_url + '.map'
            
            # Request the map file
            map_res = await client.head(map_url)
            if map_res.status_code == 200:
                print(f"[!] SOURCEMAP FOUND: {map_url}")
                found = True
            elif map_res.status_code != 404 and map_res.status_code != 403:
                print(f"[-] Unexpected status {map_res.status_code} for {map_url}")
                
        if not found:
            print("No exposed .map files found via direct probing.")
            
    finally:
        await client.aclose()

if __name__ == "__main__":
    asyncio.run(check_sourcemaps())
