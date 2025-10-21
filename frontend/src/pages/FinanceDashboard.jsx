import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";
import DataHealthPill from "@/components/DataHealthPill";
import ChecklistPanel from "@/components/ChecklistPanel";
import JobBar from "@/components/JobBar";

export default function FinanceDashboard() {
  const { currentOrgId, role } = useOrg();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const canRun = role === "OWNER" || role === "ADMIN" || role === "ANALYST";

  const load = async () => {
    setLoading(true); setError("");
    try { const { data } = await api.get(`/dashboard/finance?org_id=${currentOrgId}`); setData(data); }
    catch (e) { setError(e?.response?.data?.detail || "Failed to load"); }
    finally { setLoading(false); }
  };

  useEffect(()=>{ if(currentOrgId) load(); }, [currentOrgId]);

  const reconnect = async ()=>{
    try { const { data } = await api.post("/connections/xero/oauth/start", { org_id: currentOrgId }); window.location.href = data.auth_url; }
    catch(e){ alert(e?.response?.data?.detail || "Failed to start OAuth"); }
  };

  if (loading) return <div className="p-6">Loading...</div>;
  if (error) return <div className="p-6 text-red-600">{String(error)}</div>;

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-4" data-testid="finance-dashboard">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Finance</h1>
        <DataHealthPill connection={data?.connection} onReconnect={reconnect} onRetry={load} />
      </div>

      <JobBar canRun={canRun} />

      <div className="grid grid-cols-2 gap-3">
        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-1">Revenue (latest)</div>
          <div className="text-2xl font-bold">{data?.kpis?.revenue ?? "-"}</div>
        </div>
        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-1">DSO (days)</div>
          <div className="text-2xl font-bold">{data?.kpis?.dso_days ?? "-"}</div>
        </div>
      </div>

      <div className="border rounded bg-white p-3">
        <div className="text-sm font-medium mb-2">Trends</div>
        <div className="text-xs text-gray-600">6-month revenue series</div>
        <ul className="text-xs mt-2 list-disc ml-6">
          {(data?.series||[]).map((s)=> s.kpi==='revenue' ? s.points.map((p,i)=> (<li key={i}>{p[0]}: {p[1]}</li>)) : null)}
        </ul>
      </div>

      <ChecklistPanel />
    </div>
  );
}
