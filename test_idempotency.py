#!/usr/bin/env python3
"""
Quick test for idempotency fix
"""

import requests
import json
import time

def test_idempotency():
    base_url = "https://finance-hub-225.preview.emergentagent.com"
    
    # Setup user and org (reuse from previous test results)
    # First, let's create a new user for this test
    test_email = f"idempotency_test_{int(time.time())}@example.com"
    test_password = "TestPass123!"
    
    # Signup
    response = requests.post(f"{base_url}/api/auth/signup", json={
        "email": test_email,
        "password": test_password
    })
    print(f"Signup: {response.status_code}")
    
    # Get verification email
    time.sleep(1)
    emails_response = requests.get(f"{base_url}/api/dev/emails")
    if emails_response.status_code == 200:
        emails = emails_response.json()
        verify_email = None
        for email in emails:
            if email.get("action") == "verify_email" and email.get("to") == test_email:
                verify_email = email
                break
        
        if verify_email:
            # Verify email
            verify_response = requests.post(f"{base_url}/api/auth/verify-email", json={
                "token": verify_email["token"]
            })
            print(f"Verify: {verify_response.status_code}")
            
            # Login
            login_response = requests.post(f"{base_url}/api/auth/login", json={
                "email": test_email,
                "password": test_password
            })
            
            if login_response.status_code == 200:
                tokens = login_response.json()
                access_token = tokens["access_token"]
                
                # Create org
                org_response = requests.post(f"{base_url}/api/orgs", 
                    json={"name": f"IdempotencyTestOrg_{int(time.time())}"},
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                
                if org_response.status_code == 200:
                    org_data = org_response.json()
                    org_id = org_data["org_id"]
                    
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "X-Org-Id": org_id
                    }
                    
                    # Test idempotency
                    print("\nTesting idempotency...")
                    
                    # First request
                    response1 = requests.post(f"{base_url}/api/sync-jobs/start", 
                        json={"org_id": org_id, "type": "all_refresh"},
                        headers=headers
                    )
                    print(f"First request: {response1.status_code}")
                    if response1.status_code == 202:
                        data1 = response1.json()
                        print(f"First response: {data1}")
                        
                        # Second request immediately
                        response2 = requests.post(f"{base_url}/api/sync-jobs/start", 
                            json={"org_id": org_id, "type": "all_refresh"},
                            headers=headers
                        )
                        print(f"Second request: {response2.status_code}")
                        if response2.status_code == 202:
                            data2 = response2.json()
                            print(f"Second response: {data2}")
                            
                            # Check idempotency
                            if (data2.get("status") == "existing" and 
                                data1.get("job", {}).get("job_id") == data2.get("job", {}).get("job_id")):
                                print("✅ Idempotency test PASSED")
                                return True
                            else:
                                print("❌ Idempotency test FAILED")
                                return False
                        else:
                            print(f"Second request failed: {response2.text}")
                    else:
                        print(f"First request failed: {response1.text}")
                else:
                    print(f"Org creation failed: {org_response.text}")
            else:
                print(f"Login failed: {login_response.text}")
        else:
            print("Verification email not found")
    else:
        print(f"Failed to get emails: {emails_response.text}")
    
    return False

if __name__ == "__main__":
    test_idempotency()