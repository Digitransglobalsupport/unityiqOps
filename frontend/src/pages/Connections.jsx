import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function Connections() {
  const { currentOrgId, role } = useOrg();
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const canAdmin = ["OWNER","ADMIN"].includes(role||"");

  const load = async () => {
    setError("");
    try { const { data } = await api.get(`/connections/status?org_id=${currentOrgId}`); setStatus(data); } catch(e){ setError(e?.response?.data?.detail || "Failed to load"); }
  };

  useEffect(()=>{ if(currentOrgId) load(); }, [currentOrgId]);

  const connectXero = async () => {
    try {
      const { data } = await api.post("/connections/xero/oauth/start", { org_id: currentOrgId });
      window.location.href = data.auth_url;
    } catch (e) {
      setError(e?.response?.data?.detail?.code || e?.response?.data?.detail || "Failed to start Xero auth");
    }
  };

  const disconnectXero = async () => {
    if (!confirm("Disconnect Xero?")) return;
    try { await api.post("/connections/xero/disconnect", { org_id: currentOrgId }); await load(); } catch(e) { setError("Failed to disconnect"); }
  };

  return (
    <div className="max-w-4xl mx-auto p-6" data-testid="connections-page">
      <h1 className="text-2xl font-semibold mb-4">Connections</h1>
      {error && <div className="text-red-600 text-sm mb-2">{String(error)}</div>}

      <div className="border rounded bg-white p-4 flex items-center justify-between">
        <div>
          <div className="font-medium">Xero</div>
          <div className="text-xs text-gray-600">Read-only access for invoices and contacts. You can revoke anytime in Xero.</div>
          <div className="text-xs mt-1">Status: {status?.xero?.connected ? 'Connected' : 'Not connected'}</div>
          {status?.xero?.last_sync_at && <div className="text-xs text-gray-500">Last sync: {new Date(status.xero.last_sync_at).toLocaleString()}</div>}
          {(status?.xero?.tenants||[]).length>0 && (
            <div className="text-xs text-gray-600 mt-1">Tenants: {status.xero.tenants.join(", ")}</div>
          )}
        </div>
        <div className="flex items-center gap-2">
          {status?.xero?.connected ? (
            <button onClick={disconnectXero} className="px-3 py-1 rounded border">Disconnect</button>
          ) : (
            <button onClick={connectXero} className={`px-3 py-1 rounded ${canAdmin? 'bg-black text-white':'bg-gray-200 text-gray-500'}`} disabled={!canAdmin}>Connect to Xero</button>
          )}
        </div>
      </div>
    </div>
  );
}
