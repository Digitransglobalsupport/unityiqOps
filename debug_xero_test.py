#!/usr/bin/env python3
"""
Debug Xero connection test
"""

import requests
import json
import time

BASE_URL = "https://finance-crm-hub.preview.emergentagent.com"

def make_request(method, endpoint, data=None, headers=None):
    url = f"{BASE_URL}/api/{endpoint.lstrip('/')}"
    default_headers = {'Content-Type': 'application/json'}
    if headers:
        default_headers.update(headers)
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=default_headers, timeout=30)
        elif method.upper() == 'POST':
            response = requests.post(url, json=data, headers=default_headers, timeout=30)
        
        try:
            return response.status_code, response.json()
        except:
            return response.status_code, {"text": response.text}
    except Exception as e:
        return 0, {"error": str(e)}

def main():
    print("🔍 Debugging Xero Connection Test")
    
    # Create fresh user and org
    test_email = f"xero_debug_test_{int(time.time())}@example.com"
    test_password = "SecurePass123!"
    
    print(f"\n1. Creating user: {test_email}")
    status, response = make_request("POST", "/auth/signup", {
        "email": test_email,
        "password": test_password
    })
    print(f"   Signup: {status} - {response}")
    
    # Get verification email
    time.sleep(1)
    status, emails = make_request("GET", "/dev/emails")
    verify_token = None
    for email in emails:
        if email.get("to") == test_email and email.get("action") == "verify_email":
            verify_token = email.get("token")
            break
    
    if not verify_token:
        print("   ❌ No verification email found")
        return
    
    # Verify and login
    make_request("POST", "/auth/verify-email", {"token": verify_token})
    status, response = make_request("POST", "/auth/login", {
        "email": test_email,
        "password": test_password
    })
    
    if status != 200 or "access_token" not in response:
        print(f"   ❌ Login failed: {status} - {response}")
        return
    
    access_token = response["access_token"]
    
    # Create org and upgrade to LITE
    org_name = f"XeroTestOrg_{int(time.time())}"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    status, response = make_request("POST", "/orgs", {"name": org_name}, headers=headers)
    if status != 200 or "org_id" not in response:
        print(f"   ❌ Org creation failed: {status} - {response}")
        return
    
    org_id = response["org_id"]
    headers["X-Org-Id"] = org_id
    
    # Upgrade to LITE
    print(f"\n2. Upgrading org to LITE")
    status, response = make_request("POST", "/billing/start-lite-trial", headers=headers)
    print(f"   Upgrade: {status} - {response}")
    
    # Test Xero connection
    print(f"\n3. Testing Xero OAuth start")
    status, response = make_request("POST", "/connections/xero/oauth/start", {
        "org_id": org_id
    }, headers=headers)
    print(f"   Xero OAuth: {status} - {json.dumps(response, indent=2)}")
    
    # Check response structure
    print(f"\n4. Response analysis:")
    print(f"   Type: {type(response)}")
    print(f"   Keys: {list(response.keys()) if isinstance(response, dict) else 'Not a dict'}")
    if isinstance(response, dict):
        for key, value in response.items():
            print(f"   {key}: {type(value)} = {value}")

if __name__ == "__main__":
    main()