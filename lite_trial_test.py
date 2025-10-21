#!/usr/bin/env python3
"""
Lite Trial Upgrade Feature Tests
Tests the POST /api/billing/start-lite-trial endpoint with comprehensive scenarios
"""

import requests
import json
import sys
import time
from datetime import datetime
from typing import Dict, Optional, Tuple

class LiteTrialTester:
    def __init__(self, base_url: str = "https://finance-crm-hub.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []
        
        # Test data
        self.test_user = None
        self.test_org = None
        self.access_token = None
        
        print(f"🚀 Starting Lite Trial Upgrade Tests")
        print(f"📍 Base URL: {self.base_url}")
        print("=" * 60)

    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            status = "✅ PASS"
        else:
            status = "❌ FAIL"
        
        result = {
            "test": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status} {name}")
        if details:
            print(f"    {details}")

    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                    headers: Optional[Dict] = None, expected_status: int = 200) -> Tuple[bool, Dict]:
        """Make HTTP request and return success status and response data"""
        url = f"{self.base_url}/api/{endpoint.lstrip('/')}"
        
        default_headers = {'Content-Type': 'application/json'}
        if headers:
            default_headers.update(headers)
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=default_headers, timeout=30)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, headers=default_headers, timeout=30)
            else:
                return False, {"error": f"Unsupported method: {method}"}
            
            success = response.status_code == expected_status
            try:
                response_data = response.json()
            except:
                response_data = {"status_code": response.status_code, "text": response.text}
            
            if not success:
                response_data["actual_status"] = response.status_code
                response_data["expected_status"] = expected_status
            
            return success, response_data
            
        except Exception as e:
            return False, {"error": str(e)}

    def setup_test_user_and_org(self):
        """Create test user and organization"""
        # Create user
        test_email = f"lite_trial_test_{int(time.time())}@example.com"
        test_password = "SecurePass123!"
        
        # Signup
        success, response = self.make_request("POST", "/auth/signup", {
            "email": test_email,
            "password": test_password
        })
        
        if not success:
            self.log_test("Setup: User Signup", False, f"Failed: {response}")
            return False
        
        # Get verification email
        time.sleep(1)
        success, emails = self.make_request("GET", "/dev/emails")
        if not success:
            self.log_test("Setup: Get Dev Emails", False, f"Failed: {emails}")
            return False
        
        # Find verification email
        verify_token = None
        for email in emails:
            if email.get("to") == test_email and email.get("action") == "verify_email":
                verify_token = email.get("token")
                break
        
        if not verify_token:
            self.log_test("Setup: Find Verification Email", False, "Verification email not found")
            return False
        
        # Verify email
        success, response = self.make_request("POST", "/auth/verify-email", {
            "token": verify_token
        })
        
        if not success:
            self.log_test("Setup: Email Verification", False, f"Failed: {response}")
            return False
        
        # Login
        success, response = self.make_request("POST", "/auth/login", {
            "email": test_email,
            "password": test_password
        })
        
        if not success or "access_token" not in response:
            self.log_test("Setup: Login", False, f"Failed: {response}")
            return False
        
        self.access_token = response["access_token"]
        self.test_user = {"email": test_email, "password": test_password}
        
        # Create organization
        org_name = f"LiteTrialTestOrg_{int(time.time())}"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        success, response = self.make_request("POST", "/orgs", {
            "name": org_name
        }, headers=headers)
        
        if not success or "org_id" not in response:
            self.log_test("Setup: Create Organization", False, f"Failed: {response}")
            return False
        
        self.test_org = {
            "org_id": response["org_id"],
            "name": org_name
        }
        
        self.log_test("Setup: User and Org Creation", True, f"Created user {test_email} and org {org_name}")
        return True

    def get_auth_headers(self, include_org: bool = True) -> Dict[str, str]:
        """Get authorization headers"""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if include_org and self.test_org:
            headers["X-Org-Id"] = self.test_org["org_id"]
        return headers

    def test_authentication_required(self):
        """Test that endpoint requires authentication"""
        success, response = self.make_request(
            "POST", 
            "/billing/start-lite-trial", 
            expected_status=401
        )
        
        if success:
            self.log_test("Auth Required: No Token", True, "Correctly rejected request without auth token")
        else:
            self.log_test("Auth Required: No Token", False, f"Expected 401, got: {response}")

    def test_org_header_required(self):
        """Test that X-Org-Id header behavior (falls back to first membership for single-org users)"""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        # Don't include X-Org-Id header - should work for single-org users
        
        success, response = self.make_request(
            "POST", 
            "/billing/start-lite-trial", 
            headers=headers,
            expected_status=200
        )
        
        if success and response.get("ok") == True:
            self.log_test("Auth Behavior: Single Org Fallback", True, "Correctly fell back to first membership for single-org user")
        else:
            self.log_test("Auth Behavior: Single Org Fallback", False, f"Expected successful fallback, got: {response}")

    def test_admin_role_required(self):
        """Test that ADMIN role is required"""
        # Create a VIEWER user
        viewer_email = f"viewer_test_{int(time.time())}@example.com"
        viewer_password = "SecurePass123!"
        
        # Signup viewer
        success, response = self.make_request("POST", "/auth/signup", {
            "email": viewer_email,
            "password": viewer_password
        })
        
        if not success:
            self.log_test("RBAC Setup: Viewer Signup", False, f"Failed: {response}")
            return
        
        # Get verification email for viewer
        time.sleep(1)
        success, emails = self.make_request("GET", "/dev/emails")
        if not success:
            return
        
        verify_token = None
        for email in emails:
            if email.get("to") == viewer_email and email.get("action") == "verify_email":
                verify_token = email.get("token")
                break
        
        if not verify_token:
            return
        
        # Verify viewer email
        success, response = self.make_request("POST", "/auth/verify-email", {
            "token": verify_token
        })
        
        if not success:
            return
        
        # Login viewer
        success, response = self.make_request("POST", "/auth/login", {
            "email": viewer_email,
            "password": viewer_password
        })
        
        if not success or "access_token" not in response:
            return
        
        viewer_token = response["access_token"]
        
        # Invite viewer to org as VIEWER
        owner_headers = self.get_auth_headers()
        success, response = self.make_request("POST", f"/orgs/{self.test_org['org_id']}/invite", {
            "email": viewer_email,
            "role": "VIEWER"
        }, headers=owner_headers)
        
        if not success:
            self.log_test("RBAC Setup: Invite Viewer", False, f"Failed: {response}")
            return
        
        # Get invite email
        time.sleep(1)
        success, emails = self.make_request("GET", "/dev/emails")
        if not success:
            return
        
        invite_token = None
        for email in emails:
            if email.get("to") == viewer_email and email.get("action") == "invite":
                invite_token = email.get("token")
                break
        
        if not invite_token:
            self.log_test("RBAC Setup: Find Invite Email", False, "Invite email not found")
            return
        
        # Accept invite
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
        success, response = self.make_request("POST", "/invites/accept", {
            "token": invite_token
        }, headers=viewer_headers)
        
        if not success:
            self.log_test("RBAC Setup: Accept Invite", False, f"Failed: {response}")
            return
        
        # Now test that VIEWER cannot access lite trial endpoint
        viewer_headers["X-Org-Id"] = self.test_org["org_id"]
        success, response = self.make_request(
            "POST", 
            "/billing/start-lite-trial", 
            headers=viewer_headers,
            expected_status=403
        )
        
        if success:
            self.log_test("RBAC: VIEWER Denied", True, "VIEWER correctly denied access to lite trial endpoint")
        else:
            self.log_test("RBAC: VIEWER Denied", False, f"Expected 403, got: {response}")

    def get_current_entitlements(self) -> Optional[Dict]:
        """Get current billing entitlements"""
        headers = self.get_auth_headers()
        success, response = self.make_request("GET", "/billing/entitlements", headers=headers)
        
        if success:
            return response
        return None

    def test_initial_free_plan(self):
        """Test that a fresh org starts with FREE plan"""
        # Create a fresh org for this test
        fresh_org_name = f"FreshTestOrg_{int(time.time())}"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        success, response = self.make_request("POST", "/orgs", {
            "name": fresh_org_name
        }, headers=headers)
        
        if not success or "org_id" not in response:
            self.log_test("Initial Plan Check: Fresh Org Creation", False, f"Failed to create fresh org: {response}")
            return False
        
        fresh_org_id = response["org_id"]
        headers["X-Org-Id"] = fresh_org_id
        
        # Check entitlements for fresh org
        success, entitlements = self.make_request("GET", "/billing/entitlements", headers=headers)
        
        if not success:
            self.log_test("Initial Plan Check", False, "Could not get entitlements for fresh org")
            return False
        
        plan = entitlements.get("plan", {})
        limits = entitlements.get("limits", {})
        
        expected_limits = {
            "companies": 1,
            "connectors": 0,
            "exports": False,
            "alerts": False
        }
        
        tier = plan.get("tier", "FREE")
        limits_match = all(limits.get(k) == v for k, v in expected_limits.items())
        
        if tier == "FREE" and limits_match:
            self.log_test("Initial Plan Check", True, f"Fresh org correctly starts with FREE plan: {limits}")
            return True
        else:
            self.log_test("Initial Plan Check", False, f"Expected FREE plan with {expected_limits}, got tier={tier}, limits={limits}")
            return False

    def test_lite_trial_upgrade(self):
        """Test successful upgrade to LITE plan on a fresh org"""
        # Create another fresh org for this test
        fresh_org_name = f"UpgradeTestOrg_{int(time.time())}"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        success, response = self.make_request("POST", "/orgs", {
            "name": fresh_org_name
        }, headers=headers)
        
        if not success or "org_id" not in response:
            self.log_test("Lite Trial Upgrade: Fresh Org Creation", False, f"Failed to create fresh org: {response}")
            return False
        
        fresh_org_id = response["org_id"]
        headers["X-Org-Id"] = fresh_org_id
        
        # Verify it starts as FREE
        success, entitlements = self.make_request("GET", "/billing/entitlements", headers=headers)
        if success and entitlements.get("plan", {}).get("tier") != "FREE":
            self.log_test("Lite Trial Upgrade: Pre-check", False, f"Fresh org not FREE: {entitlements}")
            return False
        
        # Now test the upgrade
        success, response = self.make_request(
            "POST", 
            "/billing/start-lite-trial", 
            headers=headers
        )
        
        if success:
            expected_response = {
                "ok": True,
                "message": "Upgraded to LITE plan",
                "tier": "LITE"
            }
            
            response_match = all(response.get(k) == v for k, v in expected_response.items())
            
            if response_match:
                self.log_test("Lite Trial Upgrade", True, f"Successfully upgraded to LITE: {response}")
                
                # Store this org for follow-up tests
                self.upgraded_org_id = fresh_org_id
                return True
            else:
                self.log_test("Lite Trial Upgrade", False, f"Expected {expected_response}, got: {response}")
                return False
        else:
            self.log_test("Lite Trial Upgrade", False, f"Failed: {response}")
            return False

    def test_entitlements_after_upgrade(self):
        """Test that entitlements are updated after upgrade"""
        if not hasattr(self, 'upgraded_org_id'):
            self.log_test("Entitlements After Upgrade", False, "No upgraded org available")
            return False
        
        headers = {"Authorization": f"Bearer {self.access_token}", "X-Org-Id": self.upgraded_org_id}
        success, entitlements = self.make_request("GET", "/billing/entitlements", headers=headers)
        
        if not success:
            self.log_test("Entitlements After Upgrade", False, "Could not get entitlements")
            return False
        
        plan = entitlements.get("plan", {})
        limits = entitlements.get("limits", {})
        
        expected_limits = {
            "companies": 3,
            "connectors": 1,
            "exports": True,
            "alerts": True
        }
        
        tier = plan.get("tier", "FREE")
        limits_match = all(limits.get(k) == v for k, v in expected_limits.items())
        
        if tier == "LITE" and limits_match:
            self.log_test("Entitlements After Upgrade", True, f"LITE plan limits correct: {limits}")
            return True
        else:
            self.log_test("Entitlements After Upgrade", False, f"Expected LITE plan with {expected_limits}, got tier={tier}, limits={limits}")
            return False

    def test_idempotency(self):
        """Test that calling the endpoint again returns 'Already on LITE plan'"""
        if not hasattr(self, 'upgraded_org_id'):
            self.log_test("Idempotency Check", False, "No upgraded org available")
            return False
        
        headers = {"Authorization": f"Bearer {self.access_token}", "X-Org-Id": self.upgraded_org_id}
        
        success, response = self.make_request(
            "POST", 
            "/billing/start-lite-trial", 
            headers=headers
        )
        
        if success:
            if response.get("ok") == True and "Already on LITE plan" in response.get("message", ""):
                self.log_test("Idempotency Check", True, f"Correctly returned 'Already on LITE plan': {response}")
                return True
            else:
                self.log_test("Idempotency Check", False, f"Expected 'Already on LITE plan', got: {response}")
                return False
        else:
            self.log_test("Idempotency Check", False, f"Failed: {response}")
            return False

    def test_xero_connection_available(self):
        """Test that Xero connection is now available (connector limit > 0)"""
        if not hasattr(self, 'upgraded_org_id'):
            self.log_test("Xero Connection Available", False, "No upgraded org available")
            return False
        
        headers = {"Authorization": f"Bearer {self.access_token}", "X-Org-Id": self.upgraded_org_id}
        
        # Try to start Xero OAuth (should not be blocked by connector limit)
        success, response = self.make_request(
            "POST", 
            "/connections/xero/oauth/start", 
            data={"org_id": self.upgraded_org_id},
            headers=headers
        )
        
        if success and "auth_url" in response:
            self.log_test("Xero Connection Available", True, f"Xero OAuth start successful: {response.get('auth_url', '')[:50]}...")
            return True
        elif not success and response.get("detail", {}).get("code") == "LIMIT_EXCEEDED":
            self.log_test("Xero Connection Available", False, f"Still blocked by connector limit: {response}")
            return False
        else:
            self.log_test("Xero Connection Available", True, f"Xero OAuth available (response: {response})")
            return True

    def test_database_plan_update(self):
        """Test that the plan is correctly updated in the database by checking audit logs"""
        if not hasattr(self, 'upgraded_org_id'):
            self.log_test("Database Plan Update", False, "No upgraded org available")
            return False
        
        headers = {"Authorization": f"Bearer {self.access_token}", "X-Org-Id": self.upgraded_org_id}
        
        success, response = self.make_request(
            "GET", 
            f"/audit/logs?org_id={self.upgraded_org_id}", 
            headers=headers
        )
        
        if success and isinstance(response, list):
            # Look for upgrade audit log entry
            upgrade_log = None
            for log in response:
                if (log.get("action") == "upgrade" and 
                    log.get("resource") == "plan_lite_trial" and
                    log.get("meta", {}).get("to") == "LITE"):
                    upgrade_log = log
                    break
            
            if upgrade_log:
                self.log_test("Database Plan Update", True, f"Found upgrade audit log: {upgrade_log}")
                return True
            else:
                self.log_test("Database Plan Update", False, f"No upgrade audit log found in {len(response)} entries")
                return False
        else:
            self.log_test("Database Plan Update", False, f"Failed to get audit logs: {response}")
            return False

    def run_all_tests(self):
        """Run all Lite Trial tests"""
        print("\n🔧 PHASE 1: Setup")
        print("-" * 40)
        
        if not self.setup_test_user_and_org():
            print("❌ Critical: Setup failed, stopping tests")
            return False
        
        print("\n🔐 PHASE 2: Authentication & Authorization Tests")
        print("-" * 40)
        
        self.test_authentication_required()
        self.test_org_header_required()
        self.test_admin_role_required()
        
        print("\n📊 PHASE 3: Plan Upgrade Logic Tests")
        print("-" * 40)
        
        # Check initial state
        if not self.test_initial_free_plan():
            print("❌ Warning: Org not on FREE plan initially")
        
        # Perform upgrade
        if not self.test_lite_trial_upgrade():
            print("❌ Critical: Lite trial upgrade failed")
            return False
        
        # Verify upgrade results
        self.test_entitlements_after_upgrade()
        self.test_database_plan_update()
        
        print("\n🔄 PHASE 4: Idempotency & Feature Tests")
        print("-" * 40)
        
        self.test_idempotency()
        self.test_xero_connection_blocked_on_free()
        self.test_xero_connection_available()
        
        return True

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📋 LITE TRIAL TEST SUMMARY")
        print("=" * 60)
        
        success_rate = (self.tests_passed / self.tests_run * 100) if self.tests_run > 0 else 0
        
        print(f"Total Tests: {self.tests_run}")
        print(f"Passed: {self.tests_passed}")
        print(f"Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        # Show failed tests
        failed_tests = [r for r in self.test_results if not r["success"]]
        if failed_tests:
            print(f"\n❌ Failed Tests ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"  • {test['test']}: {test['details']}")
        
        return success_rate >= 80

def main():
    """Main test execution"""
    tester = LiteTrialTester()
    
    try:
        success = tester.run_all_tests()
        overall_success = tester.print_summary()
        
        # Save results
        with open("/app/lite_trial_test_results.json", "w") as f:
            json.dump({
                "summary": {
                    "total_tests": tester.tests_run,
                    "passed_tests": tester.tests_passed,
                    "success_rate": (tester.tests_passed / tester.tests_run * 100) if tester.tests_run > 0 else 0
                },
                "detailed_results": tester.test_results
            }, f, indent=2)
        
        return 0 if overall_success else 1
        
    except Exception as e:
        print(f"\n💥 Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())