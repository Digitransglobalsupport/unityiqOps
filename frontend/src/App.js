import React from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { OrgProvider } from "@/context/OrgContext";
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

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading, user } = useAuth();
  if (loading) return <div data-testid="loading" className="p-6">Loading...</div>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
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
