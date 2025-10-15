import React, { useState } from "react";
import api from "@/api/client";
import { Link, useNavigate } from "react-router-dom";

export default function SignUp() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState(null);
  const navigate = useNavigate();

  const onSubmit = async (e) => {
    e.preventDefault();
    try {
      const { data } = await api.post("/auth/signup", { email, password });
      setMessage(data.message || "Check dev emails to verify.");
      setEmail("");
      setPassword("");
      setTimeout(() => navigate("/login"), 1200);
    } catch (e) {
      setMessage(e?.response?.data?.detail || "Signup failed");
    }
  };

  return (
    <div className="max-w-md mx-auto mt-16 bg-white p-6 rounded shadow">
      <h1 className="text-xl font-semibold mb-4">Sign Up</h1>
      <form onSubmit={onSubmit} className="space-y-3">
        <div>
          <label className="block text-sm mb-1">Email</label>
          <input data-testid="signup-email" className="w-full border px-3 py-2 rounded" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
        </div>
        <div>
          <label className="block text-sm mb-1">Password</label>
          <input data-testid="signup-password" type="password" className="w-full border px-3 py-2 rounded" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
        </div>
        <button data-testid="signup-submit-button" type="submit" className="w-full bg-black text-white py-2 rounded">Create account</button>
      </form>
      {message && <div data-testid="signup-message" className="mt-3 text-sm text-gray-700">{message}</div>}
      <div className="mt-4 text-sm">
        Already have an account? <Link data-testid="signup-login-link" to="/login" className="text-blue-600">Log in</Link>
      </div>
    </div>
  );
}
