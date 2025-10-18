import React, { useEffect, useMemo, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function Connections() {
  const { currentOrgId, role } = useOrg();
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [job, setJob] = useState(null);
  const [polling, setPolling] = useState(false);
  const canAdmin = ["OWNER","ADMIN"].includes(role||"");

  const load = async () => {
    setError(""); setMessage("");
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

  const saveTenant = async (tenant_id) => {
    try { await api.post("/connections/xero/tenant", { org_id: currentOrgId, tenant_id }); await load(); } catch(e){ setError("Failed to save tenant"); }
  };

  const startBackfill = async () => {
    setError(""); setMessage("");
    try {
      const { data } = await api.post("/ingest/finance/refresh", { org_id: currentOrgId, sources: ["xero"] });
      setJob({ job_id: data.job_id, status: data.status, t0: Date.now() });
      setPolling(true);
    } catch (e) {
      setError(e?.response?.data?.detail?.code || e?.response?.data?.detail || "Failed to start backfill");
    }
  };

  useEffect(()=>{
    let timer;
    const poll = async () => {
      if (!polling || !job?.job_id) return;
      try {
        const { data } = await api.get(`/sync-jobs/${job.job_id}`);
        setJob((j)=> ({...j, ...data}));
        if (data.status === "done") {
          setMessage("Backfill completed.");
          setPolling(false);
          load();
        } else if (data.status === "error") {
          setError(typeof data.error === 'string' ? data.error : JSON.stringify(data.error));
          setPolling(false);
        } else {
          timer = setTimeout(poll, 1500);
        }
      } catch (e) {
        setError("Failed to poll job"); setPolling(false);
      }
    };
    poll();
    return ()=> { if (timer) clearTimeout(timer); };
  }, [polling, job?.job_id]);

  const tenants = useMemo(()=> status?.xero?.tenants || [], [status]);
  const defaultTenant = status?.xero?.default_tenant_id || (tenants[0]?.tenant_id);

  return (
    <div className="max-w-4xl mx-auto p-6" data-testid="connections-page">
      <h1 className="text-2xl font-semibold mb-4">Connections</h1>
      {error && <div className="text-red-600 text-sm mb-2">{String(error)}</div>}
      {message && <div className="text-green-700 text-sm mb-2">{String(message)}</div>}

      <div className="border rounded bg-white p-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="font-medium">Xero</div>
            <div className="text-xs text-gray-600">Read-only access for invoices and contacts. You can revoke anytime in Xero.</div>
            <div className="text-xs mt-1">Status: {status?.xero?.connected ? 'Connected' : 'Not connected'}</div>
            {status?.xero?.last_sync_at && <div className="text-xs text-gray-500">Last sync: {new Date(status.xero.last_sync_at).toLocaleString()}</div>}
          </div>
          <div className="flex items-center gap-2">
            {status?.xero?.connected ? (
              <>
                <button onClick={startBackfill} className={`px-3 py-1 rounded ${canAdmin? 'bg-black text-white':'bg-gray-200 text-gray-500'}`} disabled={!canAdmin || polling}>Run 3-month backfill</button>
                <button onClick={()=> saveTenant(defaultTenant)} className="px-3 py-1 rounded border" disabled={!canAdmin}>Save tenant</button>
              </>
            ) : (
              <button onClick={connectXero} className={`px-3 py-1 rounded ${canAdmin? 'bg-black text-white':'bg-gray-200 text-gray-500'}`} disabled={!canAdmin}>Connect to Xero</button>
            )}
          </div>
        </div>

        {tenants.length>0 && (
          <div className="mt-3">
            <div className="text-xs text-gray-600 mb-1">Select default tenant</div>
            <select className="border rounded px-2 py-1" value={defaultTenant || ''} onChange={(e)=> saveTenant(e.target.value)}>
              {tenants.map(t=> (
                <option key={t.tenant_id} value={t.tenant_id}>{t.name || t.tenant_id}</option>
              ))}
            </select>
          </div>
        )}

        {job && (
          <div className="mt-3 border rounded p-2 bg-gray-50">
            <div className="text-sm">Job: {job.job_id} • {job.status} {job.phase? `• ${job.phase}`: ''}</div>
            {job.counts && (
              <div className="text-xs text-gray-600">AR: {job.counts.ar||0} • AP: {job.counts.ap||0} • Contacts: {job.counts.contacts||0}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
