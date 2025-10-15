import React, { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import api from "@/api/client";

export default function ResetPassword() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [pwd, setPwd] = useState("");
  const onSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.post("/auth/reset", { token: params.get("token"), new_password: pwd });
      navigate("/login?reset=1", { replace: true });
    } catch (e) {
      alert(e?.response?.data?.detail || "Reset failed");
    }
  };
  return (
    <div className="max-w-md mx-auto mt-16 bg-white p-6 rounded shadow">
      <h1 className="text-xl font-semibold mb-4">Reset Password</h1>
      <form onSubmit={onSubmit} className="space-y-3">
        <input data-testid="reset-password-input" type="password" className="w-full border px-3 py-2 rounded" value={pwd} onChange={(e) => setPwd(e.target.value)} placeholder="New password" />
        <button data-testid="reset-password-submit" className="w-full bg-black text-white py-2 rounded">Reset</button>
      </form>
    </div>
  );
}
