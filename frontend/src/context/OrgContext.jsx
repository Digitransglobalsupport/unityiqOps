import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { tokenStore } from "@/api/client";

const OrgContext = createContext(null);

export function OrgProvider({ children }) {
  const { memberships } = useAuth();
  const [currentOrgId, setCurrentOrgId] = useState(tokenStore.orgId || null);

  useEffect(() => {
    // Ensure selected org is a valid membership
    if (memberships.length === 0) {
      tokenStore.orgId = null;
      setCurrentOrgId(null);
      return;
    }
    if (currentOrgId && memberships.some((m) => m.org_id === currentOrgId)) {
      tokenStore.orgId = currentOrgId;
      return;
    }
    // pick first membership
    const first = memberships[0];
    tokenStore.orgId = first.org_id;
    setCurrentOrgId(first.org_id);
  }, [memberships]);

  const role = useMemo(() => {
    const m = memberships.find((x) => x.org_id === currentOrgId);
    return m?.role || null;
  }, [memberships, currentOrgId]);

  const value = useMemo(() => ({ currentOrgId, setCurrentOrgId, role, memberships }), [currentOrgId, role, memberships]);
  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg() {
  return useContext(OrgContext);
}
