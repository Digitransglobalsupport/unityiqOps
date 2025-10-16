import React, { useEffect, useMemo, useState } from "react";
import { useOrg } from "@/context/OrgContext";
import { useAuth } from "@/context/AuthContext";
import api from "@/api/client";
import { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";

const Step = ({ title, help, children }) => (
  <div>
    <div className="mb-2 text-xl font-semibold">{title}</div>
    <div className="mb-4 text-sm text-gray-600">{help}</div>
    <div className="border rounded bg-white p-4">{children}</div>
  </div>
);

function Progress({ idx }) {
  return (
    <div className="w-full h-2 bg-gray-200 rounded mb-6 flex" aria-hidden>
      {[0,1,2,3].map((i)=> (
        <div key={i} className={`h-2 ${i<=idx?'bg-black':'bg-gray-300'} rounded`} style={{width:'25%'}} />
      ))}
    </div>
  );
}

export default function OnboardingWizard() {
  const { memberships, fetchMe } = useAuth();
  const { currentOrgId, setCurrentOrgId } = useOrg();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [orgName, setOrgName] = useState("");
  const [orgs, setOrgs] = useState([]);

  const [status, setStatus] = useState(null);
  const [companies, setCompanies] = useState([]);
  const [selected, setSelected] = useState({});
  const [baseCurrency, setBaseCurrency] = useState("GBP");
  const [fxSource, setFxSource] = useState("ECB");
  const [range, setRange] = useState({from:"", to:""});
  const [job, setJob] = useState(null);
  const [entitlements, setEntitlements] = useState(null);

  useEffect(()=>{
    // last 3 full months rolling
    const d = new Date();
    const first = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth()-3, 1));
    const last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 0));
    const fmt = (x)=> x.toISOString().slice(0,10);
    setRange({from: fmt(first), to: fmt(last)});
  },[]);

  const loadOrgs = async () => {
    const { data } = await api.get("/orgs");
    setOrgs(data);
  };

  const loadEntitlements = async () => {
    try {
      const { data } = await api.get("/billing/entitlements");
      setEntitlements(data);
    } catch {}
  };

  useEffect(()=>{ loadOrgs(); },[]);
  useEffect(()=>{ if(currentOrgId) loadEntitlements(); }, [currentOrgId]);

  const handleCreateOrg = async () => {
    setLoading(true); setError("");
    try {
      const { data } = await api.post("/orgs", { name: orgName || "My Org" });
      setCurrentOrgId(data.org_id);
      await fetchMe();
      setStep(1);
    } catch (e) {
      setError(e?.response?.data?.detail || "Failed to create org");
    } finally { setLoading(false); }
  };

  const handleContinueOrg = async () => {
    if (!currentOrgId) return;
    setStep(1);
  };

  const connectorsLimit = entitlements?.limits?.connectors ?? 0;
  const connectorsUsed = entitlements?.usage?.connectors ?? 0;
  const connectorsAvailable = Math.max(0, connectorsLimit - connectorsUsed);
  const connectorsDisabled = connectorsLimit === 0 || connectorsAvailable <= 0;
  const connectorsTooltip = connectorsLimit === 0
    ? "Connectors aren’t available on Free. Upgrade to Lite/Pro."
    : "Connector limit reached on Lite. Upgrade to Pro for more.";

  const connectXero = async () => {
    setLoading(true); setError("");
    try {
      const { data } = await api.post("/connections/xero/oauth/start", { org_id: currentOrgId });
      window.location.href = data.auth_url;
    } catch (e) {
      setError(e?.response?.data?.detail || "Failed to start connection");
    } finally { setLoading(false); }
  };

  const refreshStatus = async () => {
    if (!currentOrgId) return;
    try {
      const { data } = await api.get(`/connections/status?org_id=${currentOrgId}`);
      setStatus(data.xero || null);
    } catch (e) { /* ignore */ }
  };

  useEffect(()=>{ refreshStatus(); }, [currentOrgId]);

  const discoverCompanies = async () => {
    setLoading(true); setError("");
    try {
      const { data } = await api.get(`/companies/discover?org_id=${currentOrgId}`);
      setCompanies(data);
      setSelected({});
      setStep(2);
    } catch (e) {
      setError(e?.response?.data?.detail || "Discover failed");
    } finally { setLoading(false); }
  };

  const saveSelection = async () => {
    setLoading(true); setError("");
    try {
      const sel = Object.entries(selected).filter(([,v])=>v).map(([company_id])=>{
        const c = companies.find(x=>x.company_id===company_id);
        return { company_id, xero_tenant_id: c?.xero_tenant_id };
      });
      await api.post("/companies/select", { org_id: currentOrgId, companies: sel, base_currency: baseCurrency, fx_source: fxSource });
      setStep(3);
    } catch (e) {
      setError(e?.response?.data?.detail || "Save failed");
    } finally { setLoading(false); }
  };

  const companiesLimit = entitlements?.limits?.companies ?? 1;
  const companiesUsed = entitlements?.usage?.companies ?? 0;
  const companiesSelected = Object.values(selected).filter(Boolean).length;
  const companiesWouldTotal = companiesUsed + companiesSelected;
  const companiesDisabled = companiesWouldTotal > companiesLimit || companiesSelected === 0;
  const companiesTooltip = companiesLimit === 1
    ? "Free allows 1 company. Upgrade to Lite/Pro."
    : "Lite allows up to 3 companies. Upgrade to Pro for more.";

  const runSync = async () => {
    setLoading(true); setError("");
    try {
      const { data } = await api.post("/ingest/finance/refresh", { org_id: currentOrgId, from: range.from, to: range.to });
      setJob({ job_id: data.job_id, status: data.status });
      setStep(4);
    } catch (e) {
      setError(e?.response?.data?.detail || "Sync failed");
    } finally { setLoading(false); }
  };

  const disabledNext = false;
  const hasOrgs = (memberships || []).length > 0;

  return (
    <TooltipProvider>
      <div className="max-w-5xl mx-auto p-6" data-testid="onboarding-wizard">
        <Progress idx={Math.min(step,3)} />
        {step===0 && (
          <Step title="Create or choose your organisation" help="You can invite teammates later. You’re the Owner by default.">
            <div className="grid md:grid-cols-2 gap-4" data-testid="step-org">
              <div className="space-y-3">
                <div className="font-medium">Create organisation</div>
                <input data-testid="org-name-input" className="border px-3 py-2 rounded w-full" placeholder="Acme HoldCo" value={orgName} onChange={(e)=>setOrgName(e.target.value)} />
                <button data-testid="org-create-button" className="bg-black text-white px-4 py-2 rounded" onClick={handleCreateOrg} disabled={loading} aria-busy={loading}>Create</button>
              </div>
              <div className="space-y-2">
                <div className="font-medium">Choose existing</div>
                <div className="max-h-56 overflow-auto border rounded">
                  {(orgs||[]).map(o=> (
                    <label key={o.org_id} className={`flex items-center gap-2 p-2 border-b ${currentOrgId===o.org_id?'bg-green-50':''}`}>
                      <input type="radio" name="org" checked={currentOrgId===o.org_id} onChange={()=>setCurrentOrgId(o.org_id)} />
                      <div>
                        <div className="font-medium">{o.name}</div>
                        <div className="text-xs text-gray-500">{o.org_id}</div>
                      </div>
                    </label>
                  ))}
                </div>
                <button data-testid="org-continue-button" className="bg-black text-white px-4 py-2 rounded" onClick={handleContinueOrg} disabled={!currentOrgId}>Continue</button>
              </div>
            </div>
            {error && <div className="text-red-600 text-sm mt-3" role="alert" aria-live="polite">{error}</div>}
          </Step>
        )}

        {step===1 && (
          <Step title="Connect Xero" help="We use read-only scopes by default. You can revoke any time.">
            <div className="space-y-4" data-testid="step-connect-xero">
              <div className="flex items-center gap-2">
                <span className={`text-xs px-2 py-1 rounded ${status?.connected?'bg-green-100 text-green-800':'bg-gray-100 text-gray-700'}`}>{status?.connected? 'Connected' : 'Not Connected'}</span>
                {status?.last_sync_at && <span className="text-xs text-gray-500">Last sync: {new Date(status.last_sync_at).toLocaleString()}</span>}
              </div>
              {!status?.connected && (
                <div className="flex items-center gap-2">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button data-testid="xero-connect-button" className={`px-4 py-2 rounded ${connectorsDisabled? 'bg-gray-200 text-gray-500':'bg-black text-white'}`} onClick={()=>{ if(!connectorsDisabled) connectXero(); }} disabled={connectorsDisabled || loading} aria-busy={loading}>Connect</button>
                    </TooltipTrigger>
                    {connectorsDisabled && <TooltipContent side="top">{connectorsTooltip}</TooltipContent>}
                  </Tooltip>
                  <button data-testid="xero-skip-button" className="px-4 py-2 rounded border" onClick={()=>setStep(2)}>Skip for now</button>
                </div>
              )}
              {status?.connected && (
                <div>
                  <div className="text-sm mb-2">Tenants</div>
                  <ul className="list-disc ml-6 text-sm">
                    {(status.tenants||[]).map((t,i)=>(<li key={i}>{t}</li>))}
                  </ul>
                  <div className="mt-3 text-xs text-gray-500">Reconnect/Disconnect disabled in mock mode.</div>
                  <button data-testid="xero-continue-button" className="mt-4 bg-black text-white px-4 py-2 rounded" onClick={discoverCompanies}>Continue</button>
                </div>
              )}
              {error && <div className="text-red-600 text-sm" role="alert" aria-live="polite">{error}</div>}
            </div>
          </Step>
        )}

        {step===2 && (
          <Step title="Choose companies and currency" help="We’ll normalise to your base currency for roll-up reporting.">
            <div className="space-y-4" data-testid="step-select-entities">
              <button onClick={discoverCompanies} className="text-xs underline">Reload companies</button>
              <table className="w-full text-sm border">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="text-left p-2">Include</th>
                    <th className="text-left p-2">Name</th>
                    <th className="text-left p-2">Tenant</th>
                    <th className="text-left p-2">Currency</th>
                  </tr>
                </thead>
                <tbody>
                  {companies.map(c=> (
                    <tr key={c.company_id} className="border-t">
                      <td className="p-2"><input type="checkbox" checked={!!selected[c.company_id]} onChange={(e)=> setSelected(s=> ({...s, [c.company_id]: e.target.checked}))} /></td>
                      <td className="p-2">{c.name}</td>
                      <td className="p-2">{c.xero_tenant_id}</td>
                      <td className="p-2">{c.currency}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="flex gap-2 items-center">
                <label className="text-sm">Base currency</label>
                <select className="border rounded px-2 py-1" value={baseCurrency} onChange={(e)=>setBaseCurrency(e.target.value)}>
                  <option value="GBP">GBP</option>
                  <option value="USD">USD</option>
                  <option value="EUR">EUR</option>
                </select>
                <label className="text-sm ml-4">FX source</label>
                <label className="text-sm"><input type="radio" name="fx" checked={fxSource==='ECB'} onChange={()=>setFxSource('ECB')} /> ECB</label>
                <label className="text-sm ml-2"><input type="radio" name="fx" checked={fxSource==='STATIC'} onChange={()=>setFxSource('STATIC')} /> STATIC</label>
              </div>
              <Tooltip>
                <TooltipTrigger asChild>
                  <button data-testid="entities-save-button" className={`px-4 py-2 rounded ${companiesDisabled? 'bg-gray-200 text-gray-500':'bg-black text-white'}`} onClick={()=>{ if(!companiesDisabled) saveSelection(); }} disabled={companiesDisabled || loading} aria-busy={loading}>Save selection</button>
                </TooltipTrigger>
                {companiesDisabled && <TooltipContent side="top">{companiesTooltip}</TooltipContent>}
              </Tooltip>
              {error && <div className="text-red-600 text-sm" role="alert" aria-live="polite">{error}</div>}
            </div>
          </Step>
        )}

        {step===3 && (
          <Step title="Run your first snapshot" help="This builds your baseline KPIs and Synergy Score.">
            <div className="space-y-4" data-testid="step-sync-setup">
              <div className="flex gap-2 items-center">
                <label className="text-sm">From</label>
                <input data-testid="sync-from" className="border px-2 py-1 rounded" value={range.from} onChange={(e)=>setRange(r=>({...r, from:e.target.value}))} />
                <label className="text-sm">To</label>
                <input data-testid="sync-to" className="border px-2 py-1 rounded" value={range.to} onChange={(e)=>setRange(r=>({...r, to:e.target.value}))} />
              </div>
              <button data-testid="run-first-sync" className="bg-black text-white px-4 py-2 rounded" onClick={runSync} disabled={loading} aria-busy={loading}>Run first sync</button>
              {job && <div className="text-sm">Job: {job.job_id} • {job.status}</div>}
              {error && <div className="text-red-600 text-sm" role="alert" aria-live="polite">{error}</div>}
              {job?.status==='ok' && (
                <a data-testid="view-finance-dashboard" href="/dashboard/finance" className="inline-block mt-2 underline">View Finance Dashboard</a>
              )}
            </div>
          </Step>
        )}

        {step===4 && (
          <div className="p-4">Done! <a className="underline" href="/dashboard/finance">Go to Finance Dashboard</a></div>
        )}
      </div>
    </TooltipProvider>
  );
}
