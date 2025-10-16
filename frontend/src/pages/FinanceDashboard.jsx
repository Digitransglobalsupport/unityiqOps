import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";
import TrendsCharts from "@/components/TrendsCharts";
import { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";

function SynergyGauge({ score, weights, drivers }) {
  const pct = Math.max(0, Math.min(100, Number(score || 0)));
  const tooltip = `Weights: gm ${weights?.gm ?? 0}, opex ${weights?.opex ?? 0}, dso ${weights?.dso ?? 0}\nDrivers: gmΔ ${drivers?.gm_delta_pct ?? '-'}pp, opexΔ ${drivers?.opex_delta_pct ?? '-'}pp, dsoΔ ${drivers?.dso_delta_days ?? '-'} days`;
  return (
    <div data-testid="synergy-gauge" className="p-4 border rounded bg-white" title={tooltip}>
      <div className="text-sm text-gray-600">Synergy Score (Finance)</div>
      <div className="text-4xl font-bold">{pct}</div>
      <div className="text-xs text-gray-500">Why {pct}? Hover for details.</div>
    </div>
  );
}

function SnapshotBanner({ entitlements, prefs, onDismiss }) {
  const { currentOrgId } = useOrg();
  const [loading, setLoading] = useState(false);
  const show = (prefs?.show_snapshot_banner ?? true) && !!entitlements?.limits?.exports;

  const generate = async () => {
    setLoading(true);
    try {
      const d = new Date();
      const to = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 0)).toISOString().slice(0, 10);
      const from = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 3, 1)).toISOString().slice(0, 10);
      const resp = await api.post("/snapshot/generate", { org_id: currentOrgId, from, to }, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([resp.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = "synergy_snapshot.pdf";
      a.click();
    } catch (e) {
      // optional toast
    } finally {
      setLoading(false);
    }
  };

  if (!show) return null;
  return (
    <div className="border rounded bg-green-50 p-3" data-testid="snapshot-success-banner">
      <div className="text-sm">
        🎉 Snapshot unlocked.<br />
        Connect or refresh data and generate your 3-day report.
      </div>
      <div className="mt-2 flex gap-2">
        <button data-testid="generate-snapshot" onClick={generate} className="px-3 py-1 rounded bg-green-600 text-white" disabled={loading}>
          {loading ? "Generating..." : "Generate Snapshot"}
        </button>
        <button data-testid="snapshot-dismiss" onClick={onDismiss} className="px-3 py-1 rounded border">
          Dismiss
        </button>
      </div>
      <div className="text-xs text-gray-700 mt-1">You can dismiss this anytime in Settings.</div>
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
      {items.map((it) => (
        <div key={it.key} className="border rounded bg-white p-3">
          <div className="text-xs text-gray-500">{it.label}</div>
          <div className="text-lg font-semibold">{kpis?.[it.key] ?? "-"}</div>
        </div>
      ))}
    </div>
  );
}

function CompaniesTable({ companies }) {
  const badge = (p) => {
    if (p >= 80)
      return (
        <span className="text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded">Top 20%</span>
      );
    if (p >= 30)
      return (
        <span className="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded">Middle 50%</span>
      );
    return (
      <span className="text-xs bg-red-100 text-red-800 px-2 py-0.5 rounded">Bottom 30%</span>
    );
  };
  const list = [...(companies || [])].sort((a, b) => (b?.score?.s_fin || 0) - (a?.score?.s_fin || 0));
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
          {list.map((c) => (
            <tr key={c.company_id} className="border-t">
              <td className="p-2">{c.name}</td>
              <td className="p-2">{c.currency}</td>
              <td className="p-2">{c.kpis?.revenue ?? "-"}</td>
              <td className="p-2">{c.kpis?.gm_pct ?? "-"}</td>
              <td className="p-2">{c.kpis?.opex ?? "-"}</td>
              <td className="p-2">{c.kpis?.ebitda ?? "-"}</td>
              <td className="p-2">{c.kpis?.dso_days ?? "-"}</td>
              <td className="p-2">{c.score?.s_fin ?? "-"}</td>
              <td className="p-2">{typeof c.percentile === "number" ? badge(c.percentile) : "-"}</td>
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
      <div className="text-xs text-gray-600">Stale days: {health?.stale_days ?? "-"}</div>
      {(health?.warnings || []).length > 0 && (
        <ul className="list-disc ml-6 text-xs text-yellow-800 mt-2">
          {health.warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
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
        <div>
          Shared accounts: <span className="font-semibold">{lens.shared_accounts}</span>
        </div>
        <div>
          Cross-sell: <span className="font-semibold">{lens.cross_sell_count}</span>
        </div>
        <div>
          EV: <span className="font-semibold">£{lens.cross_sell_value}</span>
        </div>
      </div>
      <div className="mt-3">
        <div className="text-xs text-gray-500 mb-1">Top opportunities</div>
        <ul className="space-y-1">
          {(lens.recent_opps || []).map((o, i) => (
            <li key={i} className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2">
                <span className="font-medium">{o.name || o.master_id}</span>
                <div className="flex gap-1">
                  {(o.companies || []).map((c, ci) => (
                    <span key={ci} className="text-xs bg-gray-100 px-1.5 py-0.5 rounded">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
              <div className="text-xs">EV £{o.expected_value} • {o.nba}</div>
            </li>
          ))}
        </ul>
        <a href="/dashboard/customers" className="inline-block mt-2 text-sm underline" data-testid="view-all-customers">
          View all customers
        </a>
      </div>
    </div>
  );
}

export default function FinanceDashboard() {
  const { currentOrgId, role } = useOrg();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [entitlements, setEntitlements] = useState(null);
  const [prefs, setPrefs] = useState({ show_snapshot_banner: true });
  const [alertsMsg, setAlertsMsg] = useState("");

  const fetchData = async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await api.get(`/dashboard/finance?org_id=${currentOrgId}`);
      setData(data);
    } catch (e) {
      setError(e?.response?.data?.detail || "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  };

  const loadEntitlements = async () => {
    try {
      const { data } = await api.get("/billing/entitlements");
      setEntitlements(data);
    } catch {}
  };

  const loadPrefs = async () => {
    try {
      const { data } = await api.get("/orgs/prefs");
      setPrefs(data.ui_prefs || { show_snapshot_banner: true });
    } catch {}
  };

  useEffect(() => {
    if (!currentOrgId) return;
    fetchData();
    loadEntitlements();
    loadPrefs();
    // eslint-disable-next-line
  }, [currentOrgId]);

  const dismissBanner = async () => {
    try {
      await api.put("/orgs/prefs", { ui_prefs: { show_snapshot_banner: false } });
      setPrefs((p) => ({ ...p, show_snapshot_banner: false }));
    } catch {}
  };

  const exportDisabled = entitlements && !entitlements?.limits?.exports;
  const exportTooltip = (
    <div className="space-y-1">
      <div>Exports are available on Lite and Pro.</div>
      <div>
        <a className="underline" href="#" onClick={async (e)=>{ e.preventDefault(); try{ const { data } = await api.post('/billing/checkout', { org_id: currentOrgId, plan: 'LITE' }); window.location.href = data.url; }catch{}}}>Upgrade now</a>
      </div>
    </div>
  );

  const sendTestAlert = async () => {
    setAlertsMsg("");
    try {
      await api.post("/alerts/test", { org_id: currentOrgId });
      setAlertsMsg("Alert sent via configured channels (mock dev emails if Slack not set).");
    } catch (e) {
      setAlertsMsg(e?.response?.data?.detail?.code === "PLAN_NOT_ALLOWED" ? "Alerts are available on Lite and Pro." : "Failed to send alert");
    }
  };

  if (loading) return <div className="p-6">Loading...</div>;
  if (error) return <div className="p-6 text-red-600">{String(error)}</div>;

  return (
    <TooltipProvider>
      <div className="max-w-5xl mx-auto p-6 space-y-4" data-testid="finance-dashboard">
        {/* Banner */}
        <SnapshotBanner entitlements={entitlements} prefs={prefs} onDismiss={dismissBanner} />

        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold">Finance</h1>
          <div className="flex items-center gap-2">
            {/* Export Snapshot button with gating */}
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  data-testid="export-snapshot"
                  className={`px-3 py-1 rounded ${exportDisabled ? 'bg-gray-200 text-gray-500' : 'bg-black text-white'}`}
                  onClick={async () => {
                    if (exportDisabled) return;
                    try {
                      const d = new Date();
                      const to = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 0)).toISOString().slice(0, 10);
                      const from = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 3, 1)).toISOString().slice(0, 10);
                      const resp = await api.post("/snapshot/generate", { org_id: currentOrgId, from, to }, { responseType: "blob" });
                      const url = window.URL.createObjectURL(new Blob([resp.data]));
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = "synergy_snapshot.pdf";
                      a.click();
                    } catch {}
                  }}
                  disabled={exportDisabled}
                >
                  Export Snapshot
                </button>
              </TooltipTrigger>
              {exportDisabled && (
                <TooltipContent side="bottom">{exportTooltip}</TooltipContent>
              )}
            </Tooltip>
            {/* Upgrade CTA with helper subtext */}
            <div className="ml-2 text-right">
              <button data-testid="upgrade-snapshot" className="px-3 py-1 rounded bg-amber-500 text-white" onClick={async ()=>{ try{ const { data } = await api.post('/billing/checkout', { org_id: currentOrgId, plan: 'LITE' }); window.location.href = data.url; }catch(e){ alert(e?.response?.data?.detail || 'Checkout failed'); } }}>
                Upgrade to Snapshot (£997)
              </button>
              <div className="text-[11px] text-gray-500">3-day report with cross-sell and vendor savings.</div>
            </div>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-3">
          <SynergyGauge score={data?.score?.s_fin} weights={data?.score?.weights} drivers={data?.score?.drivers} />
          <KpiCards kpis={data?.kpis} />
          <DataHealth health={data?.data_health} />
        </div>

        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-2">Trends</div>
          <TrendsCharts series={data?.series} />
        </div>

        <CustomerLensCard lens={data?.customer_lens} />

        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-2">Alerts</div>
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  data-testid="send-test-alert"
                  className={`px-3 py-1 rounded ${entitlements?.limits?.alerts ? 'bg-indigo-600 text-white' : 'bg-gray-200 text-gray-500'}`}
                  onClick={() => { if (entitlements?.limits?.alerts) sendTestAlert(); }}
                  disabled={!entitlements?.limits?.alerts}
                >
                  Send test alert
                </button>
              </TooltipTrigger>
              {!entitlements?.limits?.alerts && (
                <TooltipContent side="top">Alerts are available on Lite and Pro.</TooltipContent>
              )}
            </Tooltip>
            {alertsMsg && <div className="text-xs text-gray-700">{alertsMsg}</div>}
          </div>
        </div>

        <CompaniesTable companies={data?.companies} />
      </div>
    </TooltipProvider>
  );
}
