import requests

url = "http://localhost:30080/api/test?file=../something"
headers = {
    "Host": "littleboys.biz"
}

print("Triggering Path Traversal exploit simulation...")
try:
    resp = requests.get(url, headers=headers, timeout=10)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text[:200]}")
except Exception as e:
    print(f"Error: {e}")
