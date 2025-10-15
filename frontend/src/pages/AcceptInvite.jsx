import React, { useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import api from "@/api/client";

export default function AcceptInvite() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  useEffect(() => {
    const token = params.get("token");
    if (!token) return;
    (async () => {
      try {
        await api.post("/invites/accept", { token });
        navigate("/", { replace: true });
      } catch (e) {
        navigate("/login?invite=0", { replace: true });
      }
    })();
  }, [params, navigate]);
  return <div className="p-6" data-testid="accept-invite-page">Accepting invite...</div>;
}
