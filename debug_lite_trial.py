#!/usr/bin/env python3
"""
Debug script to understand the Lite Trial issue
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
    print("🔍 Debugging Lite Trial Issue")
    
    # Create fresh user and org
    test_email = f"debug_test_{int(time.time())}@example.com"
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
    
    print(f"   Found verification token: {verify_token[:20]}...")
    
    # Verify email
    status, response = make_request("POST", "/auth/verify-email", {
        "token": verify_token
    })
    print(f"   Verify: {status} - {response}")
    
    # Login
    status, response = make_request("POST", "/auth/login", {
        "email": test_email,
        "password": test_password
    })
    
    if status != 200 or "access_token" not in response:
        print(f"   ❌ Login failed: {status} - {response}")
        return
    
    access_token = response["access_token"]
    print(f"   Login successful, token: {access_token[:20]}...")
    
    # Create org
    org_name = f"DebugOrg_{int(time.time())}"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    print(f"\n2. Creating org: {org_name}")
    status, response = make_request("POST", "/orgs", {
        "name": org_name
    }, headers=headers)
    
    if status != 200 or "org_id" not in response:
        print(f"   ❌ Org creation failed: {status} - {response}")
        return
    
    org_id = response["org_id"]
    print(f"   Org created: {org_id}")
    
    # Check initial entitlements
    headers["X-Org-Id"] = org_id
    
    print(f"\n3. Checking initial entitlements")
    status, response = make_request("GET", "/billing/entitlements", headers=headers)
    print(f"   Entitlements: {status} - {json.dumps(response, indent=2)}")
    
    # Try lite trial without X-Org-Id header
    print(f"\n4. Testing lite trial WITHOUT X-Org-Id header")
    headers_no_org = {"Authorization": f"Bearer {access_token}"}
    status, response = make_request("POST", "/billing/start-lite-trial", headers=headers_no_org)
    print(f"   No X-Org-Id: {status} - {response}")
    
    # Try lite trial WITH X-Org-Id header
    print(f"\n5. Testing lite trial WITH X-Org-Id header")
    status, response = make_request("POST", "/billing/start-lite-trial", headers=headers)
    print(f"   With X-Org-Id: {status} - {response}")
    
    # Check entitlements after
    print(f"\n6. Checking entitlements after trial")
    status, response = make_request("GET", "/billing/entitlements", headers=headers)
    print(f"   Final entitlements: {status} - {json.dumps(response, indent=2)}")

if __name__ == "__main__":
    main()