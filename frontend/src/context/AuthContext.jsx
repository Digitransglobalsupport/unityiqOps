import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import api, { tokenStore } from "@/api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [memberships, setMemberships] = useState([]);
  const [loading, setLoading] = useState(true);

  const isAuthenticated = !!tokenStore.access;

  const fetchMe = async () => {
    try {
      const { data } = await api.get("/me");
      setUser(data.user);
      setMemberships(data.memberships || []);
    } catch (e) {
      setUser(null);
      setMemberships([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) fetchMe();
    else setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = async (email, password) => {
    const { data } = await api.post("/auth/login", { email, password });
    tokenStore.access = data.access_token;
    tokenStore.refresh = data.refresh_token;
    await fetchMe();
    return data;
  };

  const logout = () => {
    tokenStore.access = null;
    tokenStore.refresh = null;
    setUser(null);
    setMemberships([]);
    window.location.href = "/login";
  };

  const value = useMemo(() => ({ user, memberships, isAuthenticated, fetchMe, login, logout, loading }), [user, memberships, isAuthenticated, loading]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
