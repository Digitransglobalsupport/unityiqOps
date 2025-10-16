import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";
import TrendsCharts from "@/components/TrendsCharts";
import { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";
import { Line } from "react-chartjs-2";
import "chart.js/auto";

function SynergyGauge({ score, weights, drivers }) {
  const pct = Math.max(0, Math.min(100, Number(score || 0)));
  const [open, setOpen] = useState(false);
  return (
    <div className="p-4 border rounded bg-white" data-testid="synergy-gauge">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-sm text-gray-600">Synergy Score (Finance)</div>
          <div className="text-4xl font-bold">{pct}</div>
        </div>
        <button data-testid="score-drivers-trigger" className="text-xs underline" onClick={()=>setOpen(o=>!o)}>Why this score?</button>
      </div>
      {open && (
        <div data-testid="score-drivers-panel" className="mt-2 text-xs text-gray-700 border rounded p-2 bg-gray-50">
          {drivers ? (
            <div className="space-y-1">
              <div>Weights: gm {weights?.gm ?? 0}, opex {weights?.opex ?? 0}, dso {weights?.dso ?? 0}</div>
              <div>Drivers: gmΔ {drivers?.gm_delta_pct ?? '-'}pp, opexΔ {drivers?.opex_delta_pct ?? '-'}pp, dsoΔ {drivers?.dso_delta_days ?? '-'} days</div>
              {(drivers?.notes||[]).length>0 && (
                <ul className="list-disc ml-5">
                  {drivers.notes.map((n,i)=>(<li key={i}>{n}</li>))}
                </ul>
              )}
            </div>
          ) : (
            <div>No driver details available yet.</div>
          )}
        </div>
      )}
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


function DemoBanner({ flags, prefs, onDismiss }) {
  const show = (flags?.demo_seeded === true) && (prefs?.show_demo_banner ?? true);
  if (!show) return null;
  return (
    <div className="border rounded bg-blue-50 p-3" data-testid="demo-banner">
      <div className="text-sm">Demo data loaded—replace with real connections anytime.</div>
      <div className="mt-2 flex gap-2">
        <a data-testid="view-sample-report" href="#" onClick={(e)=>{ e.preventDefault(); const btn = document.querySelector('[data-testid="export-snapshot"]'); if(btn) btn.click(); }} className="px-3 py-1 rounded bg-blue-600 text-white">View Sample Report</a>
        <a data-testid="connect-real-data" href="/onboarding" className="px-3 py-1 rounded border">Connect real data</a>
        <button data-testid="demo-dismiss" onClick={onDismiss} className="px-3 py-1 rounded border">Dismiss</button>
      </div>
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
function Sparkline({ id, points, label }) {
  if (!points || points.length < 2) return <div className="text-xs text-gray-500">Not enough data</div>;
  const labels = points.map(p=>p[0]);
  const data = points.map(p=>Number(p[1]||0));
  const ds = {
    labels,
    datasets:[{
      data,
      borderColor: '#111827',
      backgroundColor: 'rgba(17,24,39,0.1)',
      borderWidth: 1,
      pointRadius: 0,
      tension: 0.3,
    }]
  };
  const options = {
    responsive:true,
    maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{enabled:true, intersect:false}},
    scales:{x:{display:false},y:{display:false}}
  };
  return <div data-testid={`kpi-sparkline-${id}`} className="h-10"><Line data={ds} options={options} /></div>;
}

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

function DataHealth({ health, lastSyncAt }) {
  const lastSyncAge = (() => {
    try {
      if (!lastSyncAt) return "-";
      const t = new Date(lastSyncAt).getTime();
      const diffMin = Math.max(0, Math.floor((Date.now() - t) / 60000));
      if (diffMin < 60) return `${diffMin} min ago`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr} hr ago`;
      const diffDay = Math.floor(diffHr / 24);
      return `${diffDay} days ago`;
    } catch { return "-"; }
  })();
  const fxFallback = health?.fx_fallback || "-";
  return (
    <div data-testid="data-health" className="border rounded bg-white p-3">
      <div className="text-sm font-medium mb-2">Data Health</div>
      <div className="text-xs text-gray-600">Last sync: {lastSyncAge}</div>
      <div className="text-xs text-gray-600">FX fallback: {fxFallback}</div>
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
      <div className="border rounded bg-white p-3">
        <div className="text-sm font-medium mb-2">Trends</div>
        <TrendsCharts series={data?.series} />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
          <div>
            <div className="text-xs text-gray-600 mb-1">Revenue</div>
            <Sparkline id="revenue" points={(data?.trends||[]).find(s=>s.kpi==='revenue')?.points || []} label="Revenue" />
          </div>
          <div>
            <div className="text-xs text-gray-600 mb-1">GM%</div>
            <Sparkline id="gm_pct" points={(data?.trends||[]).find(s=>s.kpi==='gm_pct')?.points || []} label="GM%" />
          </div>
          <div>
            <div className="text-xs text-gray-600 mb-1">OPEX</div>
            <Sparkline id="opex" points={(data?.trends||[]).find(s=>s.kpi==='opex')?.points || []} label="OPEX" />
          </div>
          <div>
            <div className="text-xs text-gray-600 mb-1">DSO</div>
            <Sparkline id="dso_days" points={(data?.trends||[]).find(s=>s.kpi==='dso_days')?.points || []} label="DSO" />
          </div>
        </div>
      </div>

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
  const [prefs, setPrefs] = useState({ show_snapshot_banner: true, show_demo_banner: true });
  const [orgFlags, setOrgFlags] = useState({ demo_seeded: false });
  const [alertsMsg, setAlertsMsg] = useState("");

  const fetchData = async () => {
    setLoading(true);
    setError("");
    try {
      const [dash, trends] = await Promise.all([
        api.get(`/dashboard/finance?org_id=${currentOrgId}`),
        api.get(`/dashboard/finance/trends?org_id=${currentOrgId}&periods=6`)
      ]);
      setData({ ...(dash.data||{}), trends: trends.data?.series || [] });
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
      setPrefs({ show_snapshot_banner: true, show_demo_banner: true, ...(data.ui_prefs||{}) });
    } catch {}
  };

  const loadFlags = async () => {
    try {
      const { data } = await api.get("/orgs/flags");
      setOrgFlags(data.org_flags || { demo_seeded: false });
    } catch {}
  };

  useEffect(() => {
    if (!currentOrgId) return;
    fetchData();
    loadEntitlements();
    loadPrefs();
    loadFlags();
    // eslint-disable-next-line
  }, [currentOrgId]);

  const dismissBanner = async () => {
    try {
      await api.put("/orgs/prefs", { ui_prefs: { show_snapshot_banner: false } });
      setPrefs((p) => ({ ...p, show_snapshot_banner: false }));
    } catch {}
  };

  const dismissDemo = async () => {
    try {
      await api.put("/orgs/prefs", { ui_prefs: { ...prefs, show_demo_banner: false } });
      setPrefs((p)=> ({ ...p, show_demo_banner: false }));
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
        {/* Banners */}
        <DemoBanner flags={orgFlags} prefs={prefs} onDismiss={dismissDemo} />
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
          <DataHealth health={data?.data_health} lastSyncAt={data?.last_sync_at} />
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
