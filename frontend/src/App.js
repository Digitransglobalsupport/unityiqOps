import React from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { OrgProvider } from "@/context/OrgContext";
import NavBar from "@/components/NavBar";

import SignUp from "@/pages/SignUp";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Members from "@/pages/Members";
import DevEmails from "@/pages/DevEmails";

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <div data-testid="loading" className="p-6">Loading...</div>;
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/signup" element={<SignUp />} />
      <Route path="/login" element={<Login />} />
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
