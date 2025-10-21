#!/usr/bin/env python3
"""
Focused Finance Dashboard Backend API Tests
Tests CSV ingest, dashboard data, trends, export, and RBAC functionality
"""

import requests
import json
import sys
import time
import io
from datetime import datetime
from typing import Dict, Optional, List, Tuple

class FinanceBackendTester:
    def __init__(self, base_url: str = "https://finance-hub-225.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []
        
        # Test users and tokens
        self.users = {}  # email -> user_data
        self.tokens = {}  # email -> {access_token, refresh_token}
        self.orgs = {}   # org_name -> org_data
        
        print(f"🚀 Starting Finance Dashboard Backend API Tests")
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

    def setup_test_users(self):
        """Setup test users with different roles"""
        # Create OWNER user
        owner_email = f"owner_{int(time.time())}@example.com"
        success, response = self.make_request("POST", "/auth/signup", {
            "email": owner_email,
            "password": "SecurePass123!"
        })
        
        if not success:
            self.log_test("Setup: Owner Signup", False, f"Failed: {response}")
            return False
        
        # Verify owner email
        time.sleep(1)
        emails = self.get_dev_emails()
        verify_email = None
        for email in emails:
            if email.get("action") == "verify_email" and email.get("to") == owner_email:
                verify_email = email
                break
        
        if verify_email and verify_email.get("token"):
            success, response = self.make_request("POST", "/auth/verify-email", {
                "token": verify_email["token"]
            })
            if success:
                self.log_test("Setup: Owner Email Verified", True, "Owner email verified")
            else:
                self.log_test("Setup: Owner Email Verified", False, f"Failed: {response}")
                return False
        else:
            self.log_test("Setup: Owner Email Verified", False, "Verification email not found")
            return False
        
        # Login owner
        success, response = self.make_request("POST", "/auth/login", {
            "email": owner_email,
            "password": "SecurePass123!"
        })
        
        if success and "access_token" in response:
            self.tokens[owner_email] = {
                "access_token": response["access_token"],
                "refresh_token": response["refresh_token"]
            }
            self.users[owner_email] = {"role": "OWNER"}
            self.log_test("Setup: Owner Login", True, "Owner logged in successfully")
        else:
            self.log_test("Setup: Owner Login", False, f"Failed: {response}")
            return False
        
        # Create organization
        headers = {"Authorization": f"Bearer {self.tokens[owner_email]['access_token']}"}
        org_name = f"TestOrg_{int(time.time())}"
        success, response = self.make_request("POST", "/orgs", {
            "name": org_name
        }, headers=headers)
        
        if success and "org_id" in response:
            self.orgs[org_name] = {
                "org_id": response["org_id"],
                "name": org_name,
                "owner": owner_email
            }
            self.log_test("Setup: Organization Created", True, f"Org '{org_name}' created")
        else:
            self.log_test("Setup: Organization Created", False, f"Failed: {response}")
            return False
        
        return True

    def get_dev_emails(self) -> List[Dict]:
        """Get dev emails for verification"""
        success, data = self.make_request("GET", "/dev/emails")
        if success:
            return data
        return []

    def get_auth_headers(self, email: str, org_id: str = None) -> Dict[str, str]:
        """Get authorization headers for user"""
        if email not in self.tokens:
            return {}
        headers = {"Authorization": f"Bearer {self.tokens[email]['access_token']}"}
        if org_id:
            headers["X-Org-Id"] = org_id
        return headers

    def test_csv_ingest_endpoint(self):
        """Test CSV ingest endpoint with multipart form data"""
        owner_email = list(self.users.keys())[0]
        org_name = list(self.orgs.keys())[0]
        org_id = self.orgs[org_name]["org_id"]
        
        # Create sample CSV data
        pl_csv = "period,company_id,revenue,cogs,opex\n2025-01,CO1,100000,40000,30000\n2025-02,CO1,110000,44000,32000"
        ar_csv = "invoice_id,company_id,issue_date,due_date,amount,status\nINV001,CO1,2025-01-15,2025-02-15,25000,PAID\nINV002,CO1,2025-02-01,,30000,DUE"
        bs_csv = "period,company_id,receivables\n2025-01,CO1,50000\n2025-02,CO1,55000"
        
        # Prepare multipart form data
        files = {
            'org_id': (None, org_id),
            'pl': ('pl.csv', io.StringIO(pl_csv), 'text/csv'),
            'ar': ('ar.csv', io.StringIO(ar_csv), 'text/csv'),
            'bs': ('bs.csv', io.StringIO(bs_csv), 'text/csv')
        }
        
        headers = self.get_auth_headers(owner_email, org_id)
        auth_header = headers.get("Authorization")
        org_header = headers.get("X-Org-Id")
        
        try:
            response = requests.post(
                f"{self.base_url}/api/ingest/finance/csv",
                files=files,
                headers={"Authorization": auth_header, "X-Org-Id": org_header},
                timeout=30
            )
            
            success = response.status_code == 200
            try:
                response_data = response.json()
            except:
                response_data = {"status_code": response.status_code, "text": response.text}
            
            if success and response_data.get("ok"):
                ingested = response_data.get("ingested", {})
                warnings = response_data.get("warnings", [])
                self.log_test("CSV Ingest", True, f"Ingested: {ingested}, Warnings: {len(warnings)}")
                return True
            else:
                self.log_test("CSV Ingest", False, f"Failed: {response_data}")
                return False
                
        except Exception as e:
            self.log_test("CSV Ingest", False, f"Error: {str(e)}")
            return False

    def test_dashboard_finance(self):
        """Test finance dashboard endpoint"""
        owner_email = list(self.users.keys())[0]
        org_name = list(self.orgs.keys())[0]
        org_id = self.orgs[org_name]["org_id"]
        
        headers = self.get_auth_headers(owner_email, org_id)
        success, response = self.make_request("GET", f"/dashboard/finance?org_id={org_id}", headers=headers)
        
        if success:
            # Check required fields
            required_fields = ["org_id", "score", "kpis", "companies", "data_health"]
            missing_fields = [field for field in required_fields if field not in response]
            
            if not missing_fields:
                # Check score structure
                score = response.get("score", {})
                has_weights = "weights" in score
                has_drivers = "drivers" in score
                has_s_fin = "s_fin" in score
                
                self.log_test("Dashboard Finance", True, f"Dashboard loaded with score: {score.get('s_fin')}, weights: {has_weights}, drivers: {has_drivers}")
                return True
            else:
                self.log_test("Dashboard Finance", False, f"Missing fields: {missing_fields}")
                return False
        else:
            self.log_test("Dashboard Finance", False, f"Failed: {response}")
            return False

    def test_finance_trends(self):
        """Test finance trends endpoint"""
        owner_email = list(self.users.keys())[0]
        org_name = list(self.orgs.keys())[0]
        org_id = self.orgs[org_name]["org_id"]
        
        headers = self.get_auth_headers(owner_email, org_id)
        success, response = self.make_request("GET", f"/dashboard/finance/trends?org_id={org_id}&periods=6", headers=headers)
        
        if success:
            series = response.get("series", [])
            if len(series) >= 4:  # Should have 4 KPI series
                # Check each series has >= 2 points
                valid_series = []
                for s in series:
                    points = s.get("points", [])
                    if len(points) >= 2:
                        valid_series.append(s.get("kpi"))
                
                if len(valid_series) >= 4:
                    self.log_test("Finance Trends", True, f"Found {len(series)} series with >=2 points: {valid_series}")
                    return True
                else:
                    self.log_test("Finance Trends", False, f"Only {len(valid_series)} series have >=2 points")
                    return False
            else:
                self.log_test("Finance Trends", False, f"Expected 4 series, got {len(series)}")
                return False
        else:
            self.log_test("Finance Trends", False, f"Failed: {response}")
            return False

    def test_connections_status(self):
        """Test connections status endpoint"""
        owner_email = list(self.users.keys())[0]
        org_name = list(self.orgs.keys())[0]
        org_id = self.orgs[org_name]["org_id"]
        
        headers = self.get_auth_headers(owner_email, org_id)
        success, response = self.make_request("GET", f"/connections/status?org_id={org_id}", headers=headers)
        
        if success:
            xero = response.get("xero", {})
            tenants = xero.get("tenants", [])
            
            # Check tenants are objects with tenant_id and name
            valid_tenants = True
            for tenant in tenants:
                if not isinstance(tenant, dict) or "tenant_id" not in tenant or "name" not in tenant:
                    valid_tenants = False
                    break
            
            if valid_tenants:
                self.log_test("Connections Status", True, f"Found {len(tenants)} valid tenant objects")
                return True
            else:
                self.log_test("Connections Status", False, f"Invalid tenant structure: {tenants}")
                return False
        else:
            self.log_test("Connections Status", False, f"Failed: {response}")
            return False

    def test_export_snapshot_pdf(self):
        """Test PDF export endpoint"""
        owner_email = list(self.users.keys())[0]
        org_name = list(self.orgs.keys())[0]
        org_id = self.orgs[org_name]["org_id"]
        
        headers = self.get_auth_headers(owner_email, org_id)
        
        try:
            response = requests.post(
                f"{self.base_url}/api/export/snapshot",
                json={"org_id": org_id, "period_from": "2025-07-01", "period_to": "2025-09-30"},
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200 and response.headers.get('content-type') == 'application/pdf':
                pdf_size = len(response.content)
                self.log_test("Export PDF", True, f"PDF generated successfully, size: {pdf_size} bytes")
                return True
            else:
                self.log_test("Export PDF", False, f"Status: {response.status_code}, Content-Type: {response.headers.get('content-type')}")
                return False
                
        except Exception as e:
            self.log_test("Export PDF", False, f"Error: {str(e)}")
            return False

    def test_onboarding_flow(self):
        """Test basic onboarding flow endpoints"""
        owner_email = list(self.users.keys())[0]
        org_name = list(self.orgs.keys())[0]
        org_id = self.orgs[org_name]["org_id"]
        
        headers = self.get_auth_headers(owner_email, org_id)
        
        # Test Xero OAuth start
        success, response = self.make_request("POST", "/connections/xero/oauth/start", {
            "org_id": org_id
        }, headers=headers)
        
        if success and "auth_url" in response:
            self.log_test("Onboarding: Xero OAuth Start", True, f"Auth URL: {response['auth_url']}")
        else:
            self.log_test("Onboarding: Xero OAuth Start", False, f"Failed: {response}")
            return False
        
        # Test companies discover
        success, response = self.make_request("GET", f"/companies/discover?org_id={org_id}", headers=headers)
        
        if success and isinstance(response, list) and len(response) > 0:
            companies = response
            self.log_test("Onboarding: Companies Discover", True, f"Found {len(companies)} companies")
            
            # Test companies select
            success, response = self.make_request("POST", "/companies/select", {
                "org_id": org_id,
                "companies": companies[:1],  # Select first company
                "base_currency": "GBP",
                "fx_source": "ECB"
            }, headers=headers)
            
            if success:
                self.log_test("Onboarding: Companies Select", True, "Companies selected successfully")
                return True
            else:
                self.log_test("Onboarding: Companies Select", False, f"Failed: {response}")
                return False
        else:
            self.log_test("Onboarding: Companies Discover", False, f"Failed: {response}")
            return False

    def run_finance_tests(self):
        """Run all finance-specific tests"""
        print("\n🔧 PHASE 1: Test Setup")
        print("-" * 40)
        
        if not self.setup_test_users():
            print("❌ Critical: Test setup failed, stopping tests")
            return False
        
        print("\n💰 PHASE 2: Finance Dashboard Tests")
        print("-" * 40)
        
        # Test CSV ingest
        self.test_csv_ingest_endpoint()
        
        # Test dashboard endpoints
        self.test_dashboard_finance()
        self.test_finance_trends()
        self.test_connections_status()
        
        # Test PDF export
        self.test_export_snapshot_pdf()
        
        print("\n🚀 PHASE 3: Onboarding Flow Tests")
        print("-" * 40)
        
        # Test onboarding flow
        self.test_onboarding_flow()
        
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
        
        return success_rate >= 80  # Consider 80%+ success rate as passing

def main():
    """Main test execution"""
    tester = FinanceBackendTester()
    
    try:
        success = tester.run_finance_tests()
        tester.print_summary()
        
        # Save detailed results
        with open("/app/finance_test_results.json", "w") as f:
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