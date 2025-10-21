import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { tokenStore } from "@/api/client";

const OrgContext = createContext(null);

export function OrgProvider({ children }) {
  const { memberships } = useAuth();
  const [currentOrgId, _setCurrentOrgId] = useState(tokenStore.orgId || null);

  // Wrapper ensures localStorage stays in sync immediately on selection
  const setCurrentOrgId = (orgId) => {
    if (!orgId) {
      tokenStore.orgId = null;
      _setCurrentOrgId(null);
    } else {
      tokenStore.orgId = orgId;
      _setCurrentOrgId(orgId);
    }
  };

  useEffect(() => {
    // No memberships: remain orgless
    if (!Array.isArray(memberships) || memberships.length === 0) {
      setCurrentOrgId(null);
      return;
    }
    // If a stored org exists and is valid, keep it
    const stored = tokenStore.orgId;
    if (stored && memberships.some((m) => m.org_id === stored)) {
      if (currentOrgId !== stored) setCurrentOrgId(stored);
      return;
    }
    // If we already have a valid current selection, persist it
    if (currentOrgId && memberships.some((m) => m.org_id === currentOrgId)) {
      tokenStore.orgId = currentOrgId;
      return;
    }
    // Otherwise auto-select the first available membership (restores dashboards for multi‑org users too)
    setCurrentOrgId(memberships[0].org_id);
  }, [memberships]);

  const role = useMemo(() => {
    const m = (memberships||[]).find((x) => x.org_id === currentOrgId);
    return m?.role || null;
  }, [memberships, currentOrgId]);

  const value = useMemo(() => ({ currentOrgId, setCurrentOrgId, role, memberships }), [currentOrgId, role, memberships]);
  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg() {
  return useContext(OrgContext);
}
