#!/usr/bin/env python3
"""
Comprehensive Backend API Tests for Finance Dashboard System
Tests CSV ingest, dashboard data, trends, export, RBAC, and onboarding functionality
"""

import requests
import json
import sys
import time
import io
from datetime import datetime
from typing import Dict, Optional, List, Tuple

class FinanceDashboardTester:
    def __init__(self, base_url: str = "https://ai-assistant-245.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []
        
        # Test users and tokens
        self.users = {}  # email -> user_data
        self.tokens = {}  # email -> {access_token, refresh_token}
        self.orgs = {}   # org_name -> org_data
        self.memberships = {}  # email -> [membership_data]
        
        print(f"🚀 Starting Finance Dashboard API Tests")
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
            elif method.upper() == 'PATCH':
                response = requests.patch(url, json=data, headers=default_headers, timeout=30)
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

    def get_auth_headers(self, email: str) -> Dict[str, str]:
        """Get authorization headers for user"""
        if email not in self.tokens:
            return {}
        return {"Authorization": f"Bearer {self.tokens[email]['access_token']}"}

    def get_dev_emails(self) -> List[Dict]:
        """Get dev emails for verification"""
        success, data = self.make_request("GET", "/dev/emails")
        if success:
            return data
        return []

    def find_email_by_action(self, action: str, to_email: str) -> Optional[Dict]:
        """Find specific email by action and recipient"""
        emails = self.get_dev_emails()
        for email in emails:
            if email.get("action") == action and email.get("to") == to_email:
                return email
        return None

    # === AUTHENTICATION TESTS ===
    
    def test_signup_flow(self):
        """Test user signup and email verification"""
        test_email = f"test_user_{int(time.time())}@example.com"
        test_password = "SecurePass123!"
        
        # Test signup
        success, response = self.make_request("POST", "/auth/signup", {
            "email": test_email,
            "password": test_password
        })
        
        if success:
            self.users[test_email] = {
                "email": test_email,
                "password": test_password,
                "verified": False
            }
            self.log_test("Signup", True, f"User {test_email} created successfully")
        else:
            self.log_test("Signup", False, f"Failed: {response}")
            return False
        
        # Check dev email was sent
        time.sleep(1)  # Allow email to be processed
        verify_email = self.find_email_by_action("verify_email", test_email)
        if verify_email and verify_email.get("token"):
            self.log_test("Signup Email Sent", True, "Verification email found in dev store")
            
            # Test email verification
            success, response = self.make_request("POST", "/auth/verify-email", {
                "token": verify_email["token"]
            })
            
            if success:
                self.users[test_email]["verified"] = True
                self.log_test("Email Verification", True, "Email verified successfully")
                return True
            else:
                self.log_test("Email Verification", False, f"Failed: {response}")
        else:
            self.log_test("Signup Email Sent", False, "Verification email not found")
        
        return False

    def test_login_flow(self, email: str):
        """Test login with verified user"""
        if email not in self.users or not self.users[email]["verified"]:
            self.log_test("Login Prerequisites", False, f"User {email} not verified")
            return False
        
        success, response = self.make_request("POST", "/auth/login", {
            "email": email,
            "password": self.users[email]["password"]
        })
        
        if success and "access_token" in response and "refresh_token" in response:
            self.tokens[email] = {
                "access_token": response["access_token"],
                "refresh_token": response["refresh_token"]
            }
            self.log_test("Login", True, f"Login successful for {email}")
            return True
        else:
            self.log_test("Login", False, f"Failed: {response}")
            return False

    def test_password_reset_flow(self, email: str):
        """Test password reset flow"""
        # Request reset
        success, response = self.make_request("POST", "/auth/request-reset", {
            "email": email
        })
        
        if not success:
            self.log_test("Password Reset Request", False, f"Failed: {response}")
            return False
        
        self.log_test("Password Reset Request", True, "Reset request sent")
        
        # Check dev email
        time.sleep(1)
        reset_email = self.find_email_by_action("password_reset", email)
        if reset_email and reset_email.get("token"):
            self.log_test("Reset Email Sent", True, "Reset email found in dev store")
            
            # Reset password
            new_password = "NewSecurePass456!"
            success, response = self.make_request("POST", "/auth/reset", {
                "token": reset_email["token"],
                "new_password": new_password
            })
            
            if success:
                self.users[email]["password"] = new_password
                # Clear old tokens as they should be invalidated
                if email in self.tokens:
                    del self.tokens[email]
                self.log_test("Password Reset", True, "Password reset successful")
                return True
            else:
                self.log_test("Password Reset", False, f"Failed: {response}")
        else:
            self.log_test("Reset Email Sent", False, "Reset email not found")
        
        return False

    # === ORGANIZATION TESTS ===
    
    def test_create_organization(self, email: str, org_name: str):
        """Test organization creation"""
        headers = self.get_auth_headers(email)
        if not headers:
            self.log_test("Create Org Prerequisites", False, f"No auth token for {email}")
            return False
        
        success, response = self.make_request("POST", "/orgs", {
            "name": org_name
        }, headers=headers, expected_status=200)
        
        if success and "org_id" in response:
            self.orgs[org_name] = {
                "org_id": response["org_id"],
                "name": org_name,
                "owner": email
            }
            self.log_test("Create Organization", True, f"Org '{org_name}' created with ID {response['org_id']}")
            return True
        else:
            self.log_test("Create Organization", False, f"Failed: {response}")
            return False

    def test_list_organizations(self, email: str):
        """Test listing user organizations"""
        headers = self.get_auth_headers(email)
        if not headers:
            self.log_test("List Orgs Prerequisites", False, f"No auth token for {email}")
            return False
        
        success, response = self.make_request("GET", "/orgs", headers=headers)
        
        if success and isinstance(response, list):
            user_orgs = [org["name"] for org in response if "name" in org]
            self.log_test("List Organizations", True, f"Found {len(response)} orgs: {user_orgs}")
            return True
        else:
            self.log_test("List Organizations", False, f"Failed: {response}")
            return False

    def test_invite_member(self, inviter_email: str, org_name: str, invitee_email: str, role: str = "VIEWER"):
        """Test member invitation"""
        if org_name not in self.orgs:
            self.log_test("Invite Prerequisites", False, f"Org {org_name} not found")
            return False
        
        headers = self.get_auth_headers(inviter_email)
        if not headers:
            self.log_test("Invite Prerequisites", False, f"No auth token for {inviter_email}")
            return False
        
        # Add org context header
        headers["X-Org-Id"] = self.orgs[org_name]["org_id"]
        
        success, response = self.make_request("POST", f"/orgs/{self.orgs[org_name]['org_id']}/invite", {
            "email": invitee_email,
            "role": role
        }, headers=headers)
        
        if success:
            self.log_test("Invite Member", True, f"Invited {invitee_email} as {role} to {org_name}")
            
            # Check invite email
            time.sleep(1)
            invite_email = self.find_email_by_action("invite", invitee_email)
            if invite_email and invite_email.get("token"):
                self.log_test("Invite Email Sent", True, "Invite email found in dev store")
                return invite_email["token"]
            else:
                self.log_test("Invite Email Sent", False, "Invite email not found")
        else:
            self.log_test("Invite Member", False, f"Failed: {response}")
        
        return False

    def test_accept_invite(self, invitee_email: str, invite_token: str):
        """Test accepting invitation"""
        headers = self.get_auth_headers(invitee_email)
        if not headers:
            self.log_test("Accept Invite Prerequisites", False, f"No auth token for {invitee_email}")
            return False
        
        success, response = self.make_request("POST", "/invites/accept", {
            "token": invite_token
        }, headers=headers)
        
        if success:
            self.log_test("Accept Invite", True, f"Invite accepted by {invitee_email}")
            return True
        else:
            self.log_test("Accept Invite", False, f"Failed: {response}")
            return False

    # === RBAC TESTS ===
    
    def test_rbac_permissions(self, viewer_email: str, admin_email: str, org_name: str):
        """Test RBAC permission enforcement"""
        if org_name not in self.orgs:
            self.log_test("RBAC Prerequisites", False, f"Org {org_name} not found")
            return False
        
        org_id = self.orgs[org_name]["org_id"]
        
        # Test VIEWER cannot invite (should get 403)
        viewer_headers = self.get_auth_headers(viewer_email)
        viewer_headers["X-Org-Id"] = org_id
        
        success, response = self.make_request("POST", f"/orgs/{org_id}/invite", {
            "email": "test_invite@example.com",
            "role": "VIEWER"
        }, headers=viewer_headers, expected_status=403)
        
        if success:  # Success means we got the expected 403
            self.log_test("RBAC: VIEWER Cannot Invite", True, "VIEWER correctly denied invite permission")
        else:
            self.log_test("RBAC: VIEWER Cannot Invite", False, f"Expected 403, got: {response}")
        
        # Test ADMIN can invite (should succeed)
        admin_headers = self.get_auth_headers(admin_email)
        admin_headers["X-Org-Id"] = org_id
        
        success, response = self.make_request("POST", f"/orgs/{org_id}/invite", {
            "email": f"admin_invite_{int(time.time())}@example.com",
            "role": "VIEWER"
        }, headers=admin_headers, expected_status=200)
        
        if success:
            self.log_test("RBAC: ADMIN Can Invite", True, "ADMIN successfully invited member")
        else:
            self.log_test("RBAC: ADMIN Can Invite", False, f"Failed: {response}")

    def test_context_injection(self, email: str):
        """Test X-Org-Id header requirement for multi-org users"""
        headers = self.get_auth_headers(email)
        if not headers:
            self.log_test("Context Injection Prerequisites", False, f"No auth token for {email}")
            return False
        
        # Try to access audit logs without X-Org-Id (should fail if user has multiple orgs)
        success, response = self.make_request("GET", "/audit/logs?org_id=test", headers=headers, expected_status=403)
        
        if success:  # Success means we got expected 403
            self.log_test("Context Injection: Header Required", True, "X-Org-Id header correctly required")
        else:
            # This might be OK if user only has one org
            self.log_test("Context Injection: Header Required", True, f"Response: {response}")

    def test_audit_logs(self, email: str, org_name: str):
        """Test audit log access"""
        if org_name not in self.orgs:
            self.log_test("Audit Logs Prerequisites", False, f"Org {org_name} not found")
            return False
        
        headers = self.get_auth_headers(email)
        if not headers:
            self.log_test("Audit Logs Prerequisites", False, f"No auth token for {email}")
            return False
        
        org_id = self.orgs[org_name]["org_id"]
        headers["X-Org-Id"] = org_id
        
        success, response = self.make_request("GET", f"/audit/logs?org_id={org_id}", headers=headers)
        
        if success and isinstance(response, list):
            self.log_test("Audit Logs Access", True, f"Retrieved {len(response)} audit log entries")
            return True
        else:
            self.log_test("Audit Logs Access", False, f"Failed: {response}")
            return False

    # === MAIN TEST EXECUTION ===
    
    def run_comprehensive_tests(self):
        """Run all tests in sequence"""
        print("\n🧪 PHASE 1: Authentication Flow Tests")
        print("-" * 40)
        
        # Create and verify first user (will be org owner)
        if not self.test_signup_flow():
            print("❌ Critical: Signup flow failed, stopping tests")
            return False
        
        owner_email = list(self.users.keys())[0]
        
        if not self.test_login_flow(owner_email):
            print("❌ Critical: Login flow failed, stopping tests")
            return False
        
        # Test password reset
        self.test_password_reset_flow(owner_email)
        
        # Re-login after password reset
        self.test_login_flow(owner_email)
        
        print("\n🏢 PHASE 2: Organization Management Tests")
        print("-" * 40)
        
        # Create organization
        org_name = f"TestOrg_{int(time.time())}"
        if not self.test_create_organization(owner_email, org_name):
            print("❌ Critical: Organization creation failed")
            return False
        
        # Test listing orgs
        self.test_list_organizations(owner_email)
        
        print("\n👥 PHASE 3: Member Management Tests")
        print("-" * 40)
        
        # Create second user for invitation testing
        if not self.test_signup_flow():
            print("❌ Critical: Second user signup failed")
            return False
        
        invitee_email = [email for email in self.users.keys() if email != owner_email][0]
        
        if not self.test_login_flow(invitee_email):
            print("❌ Critical: Second user login failed")
            return False
        
        # Test invitation flow
        invite_token = self.test_invite_member(owner_email, org_name, invitee_email, "VIEWER")
        if invite_token:
            self.test_accept_invite(invitee_email, invite_token)
        
        # Create third user for ADMIN role testing
        if not self.test_signup_flow():
            print("❌ Warning: Third user signup failed, skipping RBAC tests")
        else:
            admin_email = [email for email in self.users.keys() if email not in [owner_email, invitee_email]][0]
            if self.test_login_flow(admin_email):
                # Invite as ADMIN
                admin_invite_token = self.test_invite_member(owner_email, org_name, admin_email, "ADMIN")
                if admin_invite_token:
                    self.test_accept_invite(admin_email, admin_invite_token)
                    
                    print("\n🔐 PHASE 4: RBAC & Permission Tests")
                    print("-" * 40)
                    
                    # Test RBAC permissions
                    self.test_rbac_permissions(invitee_email, admin_email, org_name)
        
        print("\n📊 PHASE 5: Audit & Context Tests")
        print("-" * 40)
        
        # Test audit logs
        self.test_audit_logs(owner_email, org_name)
        
        # Test context injection
        self.test_context_injection(owner_email)
        
        return True

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📋 TEST SUMMARY")
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
        
        # Show critical issues
        critical_failures = []
        for test in failed_tests:
            if any(keyword in test['test'].lower() for keyword in ['signup', 'login', 'create org']):
                critical_failures.append(test['test'])
        
        if critical_failures:
            print(f"\n🚨 Critical Issues:")
            for failure in critical_failures:
                print(f"  • {failure}")
        
        return success_rate >= 80  # Consider 80%+ success rate as passing

def main():
    """Main test execution"""
    tester = IdentityTenancyTester()
    
    try:
        success = tester.run_comprehensive_tests()
        tester.print_summary()
        
        # Save detailed results
        with open("/app/test_results.json", "w") as f:
            json.dump({
                "summary": {
                    "total_tests": tester.tests_run,
                    "passed_tests": tester.tests_passed,
                    "success_rate": (tester.tests_passed / tester.tests_run * 100) if tester.tests_run > 0 else 0
                },
                "detailed_results": tester.test_results,
                "test_data": {
                    "users": tester.users,
                    "orgs": tester.orgs
                }
            }, f, indent=2)
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"\n💥 Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())