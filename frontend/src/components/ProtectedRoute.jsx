import React from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { useOrg } from "@/context/OrgContext";

export default function ProtectedRoute({ children, minRole = "VIEWER", requireVerified = false }) {
  const { isAuthenticated, user, loading } = useAuth();
  const { currentOrgId } = useOrg();

  if (loading) return <div className="p-6">Loading...</div>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (requireVerified && !user?.email_verified) return <Navigate to="/verify" replace />;

  const ROLES = ["VIEWER","ANALYST","ADMIN","OWNER"];
  const userRole = user?.memberships?.find(m=>m.org_id===currentOrgId)?.role || user?.role || "VIEWER";
  if (ROLES.indexOf(userRole) < ROLES.indexOf(minRole)) return <Navigate to="/" replace />;

  return children;
}
