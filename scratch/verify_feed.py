import requests
import time

session = requests.Session()

# Log in
login_url = "http://127.0.0.1:5000/auth/login"
login_data = {
    "username": "admin",
    "password": "admin123"
}

print("Logging in...")
r = session.post(login_url, data=login_data, allow_redirects=False)
print("Login status:", r.status_code)

# Fetch live alerts feed
alerts_url = "http://127.0.0.1:5000/auth/api/alerts"
print("Fetching alerts feed...")
r_alerts = session.get(alerts_url)
print("Alerts status code:", r_alerts.status_code)
if r_alerts.status_code == 200:
    alerts = r_alerts.json()
    print(f"Alerts returned: {len(alerts)}")
    if alerts:
        first_alert = alerts[0]
        print("First alert details (safe print):")
        print(f"  ID: {first_alert.get('id')}")
        print(f"  Source: {first_alert.get('source')}")
        print(f"  Category: {first_alert.get('category')}")
        print(f"  Risk Score: {first_alert.get('risk_score')}")
        
        # Test blocking the alert
        alert_id = first_alert['id']
        block_url = f"http://127.0.0.1:5000/auth/api/alerts/{alert_id}/block"
        print(f"\nBlocking alert ID {alert_id}...")
        r_block = session.post(block_url)
        print("Block response status code:", r_block.status_code)
        if r_block.status_code == 200:
            block_res = r_block.json()
            print("Block response JSON:", block_res)
            
            # Check if PDF takedown notice link works
            scan_id = block_res.get('scan_id')
            pdf_url = f"http://127.0.0.1:5000/auth/api/scans/{scan_id}/takedown/pdf"
            print(f"Downloading compiled takedown notice PDF for scan {scan_id}...")
            r_pdf = session.get(pdf_url)
            print("Takedown PDF download status:", r_pdf.status_code)
            print("Takedown PDF content size:", len(r_pdf.content), "bytes")
            if r_pdf.status_code == 200:
                print("PDF Download Verification: SUCCESS!")
            else:
                print("PDF Download Verification: FAILED!")
        else:
            print("Blocking failed:", r_block.text)
    else:
        print("No alerts returned in feed.")
else:
    print("Failed to fetch alerts:", r_alerts.text)
