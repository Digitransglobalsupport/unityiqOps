import React from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import NavBar from "@/components/NavBar";
import ProtectedRoute from "@/components/ProtectedRoute";
import DevEmails from "@/pages/DevEmails";
import Login from "@/pages/Login";
import SignUp from "@/pages/SignUp";
import Dashboard from "@/pages/Dashboard";
import FinanceDashboard from "@/pages/FinanceDashboard";
import OnboardingWizard from "@/pages/OnboardingWizard";
import Members from "@/pages/Members";
import CustomersDashboard from "@/pages/CustomersDashboard";
import VendorsDashboard from "@/pages/VendorsDashboard";
import SpendIngest from "@/pages/SpendIngest";
import Verify from "@/pages/Verify";
import ResetPassword from "@/pages/ResetPassword";
import AcceptInvite from "@/pages/AcceptInvite";
import Settings from "@/pages/Settings";
import Contact from "@/pages/Contact";
import Connections from "@/pages/Connections";

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <BrowserRouter>
        <NavBar />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<SignUp />} />

          <Route path="/verify" element={<Verify />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/accept-invite" element={<AcceptInvite />} />

          <Route path="/dashboard/finance" element={<ProtectedRoute requireVerified={true}><FinanceDashboard /></ProtectedRoute>} />
          <Route path="/dashboard/customers" element={<ProtectedRoute requireVerified={true}><CustomersDashboard /></ProtectedRoute>} />
          <Route path="/dashboard/vendors" element={<ProtectedRoute requireVerified={true}><VendorsDashboard /></ProtectedRoute>} />

          <Route path="/onboarding" element={<ProtectedRoute requireVerified={true}><OnboardingWizard /></ProtectedRoute>} />
          <Route path="/members" element={<ProtectedRoute minRole="ADMIN" requireVerified={true}><Members /></ProtectedRoute>} />
          <Route path="/spend" element={<ProtectedRoute minRole="ADMIN" requireVerified={true}><SpendIngest /></ProtectedRoute>} />

          <Route path="/settings" element={<ProtectedRoute minRole="ADMIN" requireVerified={true}><Settings /></ProtectedRoute>} />
          <Route path="/connections" element={<ProtectedRoute minRole="ADMIN" requireVerified={true}><Connections /></ProtectedRoute>} />
          <Route path="/contact" element={<Contact />} />

          <Route path="/dev/emails" element={<DevEmails />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
