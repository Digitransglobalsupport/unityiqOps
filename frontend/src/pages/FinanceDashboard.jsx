import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";
import TrendsCharts from "@/components/TrendsCharts";

function SynergyGauge({ score, weights, drivers }) {
  const pct = Math.max(0, Math.min(100, Number(score||0)));
  const tooltip = `Weights: gm ${weights?.gm ?? 0}, opex ${weights?.opex ?? 0}, dso ${weights?.dso ?? 0}\nDrivers: gmΔ ${drivers?.gm_delta_pct ?? '-'}pp, opexΔ ${drivers?.opex_delta_pct ?? '-'}pp, dsoΔ ${drivers?.dso_delta_days ?? '-'} days`;
  return (
    <div data-testid="synergy-gauge" className="p-4 border rounded bg-white" title={tooltip}>
      <div className="text-sm text-gray-600">Synergy Score (Finance)</div>
      <div className="text-4xl font-bold">{pct}</div>
      <div className="text-xs text-gray-500">Why {pct}? Hover for details.</div>
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
  const badge = (p) => {
    if (p >= 80) return <span className="text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded">Top 20%</span>;
    if (p >= 30) return <span className="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded">Middle 50%</span>;
    return <span className="text-xs bg-red-100 text-red-800 px-2 py-0.5 rounded">Bottom 30%</span>;
  };
  const list = [...(companies||[])].sort((a,b)=> (b?.score?.s_fin||0) - (a?.score?.s_fin||0));
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
            <th className="text-left p-2">Percentile</th>
          </tr>
        </thead>
        <tbody>
          {list.map(c => (
            <tr key={c.company_id} className="border-t">
              <td className="p-2">{c.name}</td>
              <td className="p-2">{c.currency}</td>
              <td className="p-2">{c.kpis?.revenue ?? '-'}</td>
              <td className="p-2">{c.kpis?.gm_pct ?? '-'}</td>
              <td className="p-2">{c.kpis?.opex ?? '-'}</td>
              <td className="p-2">{c.kpis?.ebitda ?? '-'}</td>
              <td className="p-2">{c.kpis?.dso_days ?? '-'}</td>
              <td className="p-2">{c.score?.s_fin ?? '-'}</td>
              <td className="p-2">{typeof c.percentile==='number' ? badge(c.percentile) : '-'}</td>
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

function CustomerLensCard({ lens }) {
  if (!lens) return null;
  return (
    <div className="border rounded bg-white p-3" data-testid="customer-lens">
      <div className="text-sm font-medium mb-2">Customer Lens</div>
      <div className="flex gap-6 text-sm">
        <div>Shared accounts: <span className="font-semibold">{lens.shared_accounts}</span></div>
        <div>Cross-sell: <span className="font-semibold">{lens.cross_sell_count}</span></div>
        <div>EV: <span className="font-semibold">£{lens.cross_sell_value}</span></div>
      </div>
      <div className="mt-3">
        <div className="text-xs text-gray-500 mb-1">Top opportunities</div>
        <ul className="space-y-1">
          {(lens.recent_opps||[]).map((o,i)=> (
            <li key={i} className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2">
                <span className="font-medium">{o.name || o.master_id}</span>
                <div className="flex gap-1">
                  {(o.companies||[]).map((c,ci)=>(<span key={ci} className="text-xs bg-gray-100 px-1.5 py-0.5 rounded">{c}</span>))}
                </div>
              </div>
              <div className="text-xs">EV £{o.expected_value} • {o.nba}</div>
            </li>
          ))}
        </ul>
        <a href="/dashboard/customers" className="inline-block mt-2 text-sm underline" data-testid="view-all-customers">View all customers</a>
      </div>
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
          <UpgradeCta />
          <button data-testid="refresh-button" disabled={!canRefresh} className={`px-3 py-1 rounded ${canRefresh? 'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={refresh}>Refresh</button>
        </div>
      </div>
      {loading && <div>Loading...</div>}
      {error && <div className="text-red-600 text-sm" role="alert" aria-live="polite">{error}</div>}
      {data && (
        <div className="space-y-4">
          <CustomerLensCard lens={data.customer_lens} />
          <SynergyGauge score={data.score?.s_fin} weights={data.score?.weights} drivers={data.score?.drivers} />
          <TrendsCharts />
          <KpiCards kpis={data.kpis} />
          <CompaniesTable companies={data.companies} />
          <DataHealth health={data.data_health} />
          <div className="pt-2">
            <ExportSnapshot orgId={currentOrgId} />
          </div>
        </div>
      )}
    </div>
  );
}

function ExportSnapshot({ orgId }) {
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState("");
  const exportPdf = async () => {
    setLoading(true); setMsg("");
    try {
      const { data } = await api.post("/export/snapshot", { org_id: orgId, period_from: "2025-07-01", period_to: "2025-09-30" }, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([data]));
      const link = document.createElement('a');
      link.href = url; link.setAttribute('download', 'synergy_snapshot.pdf');
      document.body.appendChild(link); link.click(); link.remove();
      setMsg("Download started");
    } catch (e) { setMsg(e?.response?.data?.detail || "Export failed"); }
    finally { setLoading(false); }
  };
  return (
    <div className="flex items-center gap-2">
      <button data-testid="export-snapshot" className="px-3 py-1 rounded bg-black text-white" onClick={exportPdf} disabled={loading} aria-busy={loading}>Download Synergy Snapshot (PDF)</button>
      {msg && <div className="text-sm">{msg}</div>}
    </div>
  );
}
