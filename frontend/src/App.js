import React from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { OrgProvider, useOrg } from "@/context/OrgContext";
import NavBar from "@/components/NavBar";
import VerifyBanner from "@/components/VerifyBanner";

import SignUp from "@/pages/SignUp";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Members from "@/pages/Members";
import DevEmails from "@/pages/DevEmails";
import Verify from "@/pages/Verify";
import ResetPassword from "@/pages/ResetPassword";
import AcceptInvite from "@/pages/AcceptInvite";
import OnboardingWizard from "@/pages/OnboardingWizard";
import FinanceDashboard from "@/pages/FinanceDashboard";
import CsvIngest from "@/pages/CsvIngest";
import CrmIngest from "@/pages/CrmIngest";

function ProtectedRoute({ children, requireVerified=false, minRole=null }) {
  const { isAuthenticated, loading, user } = useAuth();
  const { role } = useOrg();
  if (loading) return <div data-testid="loading" className="p-6">Loading...</div>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (requireVerified && user && !user.email_verified) return <Navigate to="/dev/emails" replace />;
  if (minRole) {
    const order = {VIEWER:1, ANALYST:2, ADMIN:3, OWNER:4};
    if ((order[role||'']||0) < (order[minRole]||0)) return <Navigate to="/" replace />;
  }
  return (
    <>
      <VerifyBanner show={user && !user.email_verified} />
      {children}
    </>
  );
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/signup" element={<SignUp />} />
      <Route path="/login" element={<Login />} />
      <Route path="/verify" element={<Verify />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/accept-invite" element={<AcceptInvite />} />

      <Route path="/onboarding" element={
        <ProtectedRoute requireVerified={true}>
          <OnboardingWizard />
        </ProtectedRoute>
      } />

      <Route path="/dashboard/finance" element={
        <ProtectedRoute requireVerified={true} minRole="VIEWER">
          <FinanceDashboard />
        </ProtectedRoute>
      } />

      <Route path="/ingest/csv" element={
        <ProtectedRoute requireVerified={true} minRole="ANALYST">
          <CsvIngest />
        </ProtectedRoute>
      } />

      <Route path="/ingest/crm" element={
        <ProtectedRoute requireVerified={true} minRole="ANALYST">
          <CrmIngest />
        </ProtectedRoute>
      } />

      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />
      <Route
        path="/members"
        element={
          <ProtectedRoute>
            <Members />
          </ProtectedRoute>
        }
      />
      <Route path="/dev/emails" element={<DevEmails />} />
    </Routes>
  );
}

function App() {
  return (
    <div className="App min-h-screen bg-gray-50">
      <BrowserRouter>
        <AuthProvider>
          <OrgProvider>
            <NavBar />
            <AppRoutes />
          </OrgProvider>
        </AuthProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
