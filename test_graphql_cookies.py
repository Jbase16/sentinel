import asyncio
from curl_cffi import requests
import json
import sys

ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
cookie_str = sys.stdin.read().strip()
if not cookie_str.startswith("COOKIES_JSON: "):
    print("Invalid cookie input")
    sys.exit(1)

cookies = json.loads(cookie_str[len("COOKIES_JSON: "):])

print('Testing curl_cffi with UA:', ua)
print('Using cookies:', list(cookies.keys()))
res = requests.post(
    'https://api.whatnot.com/graphql', 
    headers={'Content-Type': 'application/json', 'User-Agent': ua},
    cookies=cookies,
    json={'query': '{ __schema { types { name } } }'},
    impersonate='safari'
)
print('Status Code:', res.status_code)
print('Headers:', dict(res.headers))
print(res.text[:500])
