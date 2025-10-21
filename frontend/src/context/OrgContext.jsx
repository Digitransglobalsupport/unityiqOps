import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { tokenStore } from "@/api/client";

const OrgContext = createContext(null);

export function OrgProvider({ children }) {
  const { memberships } = useAuth();
  const [currentOrgId, setCurrentOrgId] = useState(tokenStore.orgId || null);

  useEffect(() => {
    // No memberships: remain orgless
    if (!Array.isArray(memberships) || memberships.length === 0) {
      tokenStore.orgId = null;
      setCurrentOrgId(null);
      return;
    }
    // If we have exactly one membership and none selected, auto-select it
    if (!currentOrgId && memberships.length === 1) {
      tokenStore.orgId = memberships[0].org_id;
      setCurrentOrgId(memberships[0].org_id);
      return;
    }
    // If selected org is valid among memberships, persist
    if (currentOrgId && memberships.some((m) => m.org_id === currentOrgId)) {
      tokenStore.orgId = currentOrgId;
      return;
    }
    // Otherwise, remain orgless until user selects/creates one
    tokenStore.orgId = null;
    setCurrentOrgId(null);
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
