import React from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { useOrg } from "@/context/OrgContext";

export default function ProtectedRoute({ children, minRole = "VIEWER", requireVerified = false }) {
  const { isAuthenticated, user, loading } = useAuth();
  const { currentOrgId, memberships } = useOrg();

  if (loading) return <div className="p-6">Loading...</div>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (requireVerified && !user?.email_verified) return <Navigate to="/verify" replace />;

  // If user has no organisations yet, take them to onboarding
  if (requireVerified && (Array.isArray(memberships) && memberships.length === 0)) {
    return <Navigate to="/onboarding" replace />;
  }
  // If verified but no current org selected yet, also send to onboarding to pick/create one
  if (requireVerified && !currentOrgId) {
    return <Navigate to="/onboarding" replace />;
  }

  const ROLES = ["VIEWER","ANALYST","ADMIN","OWNER"];
  const userRole = (Array.isArray(user?.memberships) ? user.memberships.find(m=>m.org_id===currentOrgId)?.role : null) || user?.role || "VIEWER";
  if (ROLES.indexOf(userRole) < ROLES.indexOf(minRole)) return <Navigate to="/" replace />;

  return children;
}
