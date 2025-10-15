import React, { useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import api from "@/api/client";

export default function Verify() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  useEffect(() => {
    const token = params.get("token");
    if (!token) return;
    (async () => {
      try {
        await api.post("/auth/verify-email", { token });
        navigate("/login?verified=1", { replace: true });
      } catch (e) {
        navigate("/login?verified=0", { replace: true });
      }
    })();
  }, [params, navigate]);
  return <div className="p-6" data-testid="verify-page">Verifying...</div>;
}
