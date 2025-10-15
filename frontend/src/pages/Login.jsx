import React, { useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { Link, useNavigate } from "react-router-dom";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      await login(email, password);
      navigate("/");
    } catch (e) {
      setError(e?.response?.data?.detail || "Login failed");
    }
  };

  return (
    <div className="max-w-md mx-auto mt-16 bg-white p-6 rounded shadow">
      <h1 className="text-xl font-semibold mb-4">Log In</h1>
      <form onSubmit={onSubmit} className="space-y-3">
        <div>
          <label className="block text-sm mb-1">Email</label>
          <input data-testid="login-email" className="w-full border px-3 py-2 rounded" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
        </div>
        <div>
          <label className="block text-sm mb-1">Password</label>
          <input data-testid="login-password" type="password" className="w-full border px-3 py-2 rounded" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
        </div>
        <button data-testid="login-submit-button" type="submit" className="w-full bg-black text-white py-2 rounded">Log in</button>
      </form>
      {error && <div data-testid="login-error" className="mt-3 text-sm text-red-600">{error}</div>}
      <div className="mt-4 text-sm">
        New here? <Link data-testid="login-signup-link" to="/signup" className="text-blue-600">Create an account</Link>
      </div>
    </div>
  );
}
