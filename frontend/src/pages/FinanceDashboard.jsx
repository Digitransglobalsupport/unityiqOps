import React, { useEffect, useMemo, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

function SynergyGauge({ score }) {
  const pct = Math.max(0, Math.min(100, Number(score||0)));
  return (
    <div data-testid="synergy-gauge" className="p-4 border rounded bg-white">
      <div className="text-sm text-gray-600">Synergy Score (Finance)</div>
      <div className="text-4xl font-bold">{pct}</div>
    </div>
  );
}

function KpiCards({ kpis }) {
  const items = [
    { key: "revenue", label: "Revenue" },
    { key: "gm_pct", label: "GM%" },
    { key: "opex", label: "OPEX" },
    { key: "ebitda", label: "EBITDA" },
    { key: "dso_days", label: "DSO" },
  ];
  return (
    <div data-testid="kpi-cards" className="grid grid-cols-2 md:grid-cols-5 gap-3">
      {items.map((it)=>(
        <div key={it.key} className="border rounded bg-white p-3">
          <div className="text-xs text-gray-500">{it.label}</div>
          <div className="text-lg font-semibold">{kpis?.[it.key] ?? '-'}</div>
        </div>
      ))}
    </div>
  );
}

function CompaniesTable({ companies }) {
  return (
    <div data-testid="companies-table" className="border rounded bg-white">
      <table className="w-full text-sm">
        <thead className="bg-gray-50">
          <tr>
            <th className="text-left p-2">Company</th>
            <th className="text-left p-2">Currency</th>
            <th className="text-left p-2">Revenue</th>
            <th className="text-left p-2">GM%</th>
            <th className="text-left p-2">OPEX</th>
            <th className="text-left p-2">EBITDA</th>
            <th className="text-left p-2">DSO</th>
            <th className="text-left p-2">Score</th>
          </tr>
        </thead>
        <tbody>
          {(companies||[]).map(c => (
            <tr key={c.company_id} className="border-t">
              <td className="p-2">{c.name}</td>
              <td className="p-2">{c.currency}</td>
              <td className="p-2">{c.kpis?.revenue ?? '-'}</td>
              <td className="p-2">{c.kpis?.gm_pct ?? '-'}</td>
              <td className="p-2">{c.kpis?.opex ?? '-'}</td>
              <td className="p-2">{c.kpis?.ebitda ?? '-'}</td>
              <td className="p-2">{c.kpis?.dso_days ?? '-'}</td>
              <td className="p-2">{c.score?.s_fin ?? '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DataHealth({ health }) {
  return (
    <div data-testid="data-health" className="border rounded bg-white p-3">
      <div className="text-sm font-medium mb-2">Data Health</div>
      <div className="text-xs text-gray-600">Stale days: {health?.stale_days ?? '-'}</div>
      {(health?.warnings||[]).length>0 && (
        <ul className="list-disc ml-6 text-xs text-yellow-800 mt-2">
          {health.warnings.map((w,i)=>(<li key={i}>{w}</li>))}
        </ul>
      )}
    </div>
  );
}

export default function FinanceDashboard() {
  const { currentOrgId, role } = useOrg();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchData = async () => {
    setLoading(true); setError("");
    try {
      const { data } = await api.get(`/dashboard/finance?org_id=${currentOrgId}`);
      setData(data);
    } catch (e) {
      setError(e?.response?.data?.detail || "Failed to load dashboard");
    } finally { setLoading(false); }
  };

  useEffect(()=>{ if (currentOrgId) fetchData(); }, [currentOrgId]);

  const canRefresh = ["ANALYST","ADMIN","OWNER"].includes(role || "");
  const refresh = async () => {
    try {
      await api.post("/ingest/finance/refresh", { org_id: currentOrgId });
      fetchData();
    } catch {}
  };

  return (
    <div className="max-w-6xl mx-auto p-6" data-testid="finance-dashboard">
      <div className="flex items-center justify-between mb-4">
        <div className="text-2xl font-semibold">Finance Dashboard</div>
        <div className="flex items-center gap-2">
          <button data-testid="refresh-button" disabled={!canRefresh} className={`px-3 py-1 rounded ${canRefresh? 'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={refresh}>Refresh</button>
        </div>
      </div>
      {loading && <div>Loading...</div>}
      {error && <div className="text-red-600 text-sm" role="alert" aria-live="polite">{error}</div>}
      {data && (
        <div className="space-y-4">
          <SynergyGauge score={data.score?.s_fin} />
          <KpiCards kpis={data.kpis} />
          <CompaniesTable companies={data.companies} />
          <DataHealth health={data.data_health} />
        </div>
      )}
    </div>
  );
}
