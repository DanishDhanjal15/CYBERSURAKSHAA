import requests
import sys

# Ensure UTF-8 output on Windows terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

URL = "http://localhost:8000/api/analyze"
payload = {
    "message": "Your Binance account is about to be suspended. We detected suspicious activity. Please verify your identity immediately to protect your funds. Act fast! Visit: www.binance-secure-auth123.net"
}

try:
    response = requests.post(URL, json=payload)
    print("Status Code:", response.status_code)
    print("Response Body:", response.json())
except Exception as e:
    print("Error:", e)
    sys.exit(1)
