import asyncio
from curl_cffi import requests

ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"

print('Testing curl_cffi with NO impersonate')
res = requests.post(
    'https://api.whatnot.com/graphql/', 
    headers={'Content-Type': 'application/json', 'User-Agent': ua},
    json={'query': '{ __schema { types { name } } }'}
)
print('Status Code:', res.status_code)
print(res.text[:100])
