import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";
import { useNavigate } from "react-router-dom";
import InlineErrorBanner from "@/components/InlineErrorBanner";
import useRetriable from "@/hooks/useRetriable";

function Kpis({ summary, savings }){
  return (
    <div className="grid md:grid-cols-3 gap-3" data-testid="vendors-kpis">
      <div className="border rounded bg-white p-3"><div className="text-xs text-gray-500">Shared Vendors</div><div className="text-2xl font-semibold">{summary?.shared_vendors ?? '-'}</div></div>
      <div className="border rounded bg-white p-3"><div className="text-xs text-gray-500">Annual Spend</div><div className="text-2xl font-semibold">£{summary?.annual_spend ?? '-'}</div></div>
      <div className="border rounded bg-white p-3"><div className="text-xs text-gray-500">Est. Savings</div><div className="text-2xl font-semibold">£{savings?.est_saving ?? '-'}</div></div>
    </div>
  );
}

export default function VendorsDashboard(){
  const { currentOrgId, role } = useOrg();
  const navigate = useNavigate();
  const [vendors, setVendors] = useState([]);
  const [summary, setSummary] = useState(null);
  const [opps, setOpps] = useState([]);
  const [oppSummary, setOppSummary] = useState(null);
  const [status, setStatus] = useState('open');
  const [q, setQ] = useState('');
  const [category, setCategory] = useState('');
  const [shared, setShared] = useState('any');
  const [cats, setCats] = useState([]);
  const [msg, setMsg] = useState('');

  const canAnalyst = ["ANALYST","ADMIN","OWNER"].includes(role||"");
  const canAdmin = ["ADMIN","OWNER"].includes(role||"");

  // Retriable initial loads
  const retry = useRetriable(async () => {
    if (!currentOrgId) return;
    const { data } = await api.get(`/vendors/master?org_id=${currentOrgId}&q=${encodeURIComponent(q)}&category=${category}&shared=${shared}&limit=50`);
    setVendors(data.items||[]); setSummary(data.summary||null);
    return true;
  }, { key: `vendors-${currentOrgId}`, onSuccess: ()=>{}, onFail: ()=>{} });

  const loadVendors = async () => {
    if (!currentOrgId) return; // short-circuit when orgless
    const { data } = await api.get(`/vendors/master?org_id=${currentOrgId}&q=${encodeURIComponent(q)}&category=${category}&shared=${shared}&limit=50`);
    setVendors(data.items||[]); setSummary(data.summary||null);
  };
  const loadOpps = async () => {
    if (!currentOrgId) return; // short-circuit when orgless
    const { data } = await api.get(`/opps/savings?org_id=${currentOrgId}&status=${status}&limit=50`);
    setOpps(data.items||[]); setOppSummary(data.summary||null);
  };
  const loadCats = async () => {
    const { data } = await api.get('/vendors/categories'); setCats(data.categories||[]);
  };
  useEffect(()=>{ if (currentOrgId){ retry.start(); loadOpps(); loadCats(); } }, [currentOrgId, status, retry]);

  if (!currentOrgId) {
    return (
      <div className="max-w-3xl mx-auto p-6" data-testid="orgless-prompt">
        <h1 className="text-2xl font-semibold mb-2">Vendors</h1>
        <div className="border rounded bg-white p-6">
          <div className="text-base font-medium mb-1">Let’s connect your first company</div>
          <div className="text-sm text-gray-600 mb-4">Create or select an organisation to begin.</div>
          <div className="flex items-center gap-3">
            <button className="bg-black text-white px-4 py-2 rounded" onClick={()=> navigate('/onboarding')} data-testid="go-to-onboarding">Go to Onboarding</button>
            <a href="/about" className="text-sm underline text-gray-700">Learn more</a>
          </div>
        </div>
      </div>
    );
  }

  const moveStatus = async (opp_id, ns) => {
    try { await api.post(`/opps/savings/${opp_id}/status`, { status: ns }); setMsg('Status updated'); loadOpps(); } catch(e){ setMsg('Update failed'); }
  };
  const assignOpp = async (opp_id, user_id) => {
    try { await api.post(`/opps/savings/${opp_id}/assign`, { owner_user_id: user_id }); setMsg('Assigned'); loadOpps(); } catch(e){ setMsg('Assign failed'); }
  };

  return (
    <div className="max-w-6xl mx-auto p-6" data-testid="vendors-dashboard">
      {/* Inline error banner for retriable loads */}
      <InlineErrorBanner visible={retry.status === 'retrying' && !retry.suppressed} countdownSec={retry.nextRetrySec} onRetryNow={retry.retryNow} onDismiss={retry.dismiss} />
      
      <div className="flex items-center justify-between mb-2">
        <div className="text-2xl font-semibold">Vendors</div>
        <div data-testid="vendors-last-sync-chip" className={(() => {
          if (!summary?.last_sync_at) return "text-xs px-2 py-1 rounded bg-gray-100 text-gray-700";
          const ageH = (Date.now() - new Date(summary.last_sync_at).getTime()) / 3600000;
          if (ageH > 72) return "text-xs px-2 py-1 rounded bg-red-100 text-red-700";
          if (ageH > 24) return "text-xs px-2 py-1 rounded bg-yellow-100 text-yellow-800";
          return "text-xs px-2 py-1 rounded bg-gray-100 text-gray-700";
        })()}>Last sync: {summary?.last_sync_at ? new Date(summary.last_sync_at).toLocaleString() : '—'}</div>
      </div>
      <Kpis summary={summary} savings={oppSummary} />

      <div className="mt-4 grid md:grid-cols-3 gap-4" data-testid="vendors-board">
        {['open','validate','action'].map(col => (
          <div key={col} className="border rounded bg-white p-2">
            <div className="text-sm font-medium mb-2">{col[0].toUpperCase()+col.slice(1)}</div>
            <div className="space-y-2">
              {opps.filter(o=>o.status===col).map(o => (
                <div key={o.opportunity_id} className="border rounded p-2">
                  <div className="text-sm font-medium">{(o.vendors||[]).join(', ')} • £{o.est_saving}</div>
                  <div className="text-xs text-gray-500">{(o.companies||[]).map((c,i)=>(<span key={i} className="bg-gray-100 px-1 rounded mr-1">{c}</span>))}</div>
                  <div className="text-xs mt-1">{o.playbook_step}</div>
                  <div className="mt-2 flex gap-2">
                    {canAnalyst && <button className="text-xs border rounded px-2" onClick={()=>assignOpp(o.opportunity_id, 'USR2')}>Assign</button>}
                    {canAdmin && ['open','validate','action','won','lost'].map(ns=> (
                      <button key={ns} className="text-xs border rounded px-2" onClick={()=>moveStatus(o.opportunity_id, ns)}>{ns}</button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        <div className="border rounded bg-white p-2">
          <div className="text-sm font-medium mb-2">Won</div>
          <div className="space-y-2">{opps.filter(o=>o.status==='won').map(o => (<div key={o.opportunity_id} className="border rounded p-2 text-xs">{(o.vendors||[]).join(', ')} • £{o.est_saving}</div>))}</div>
          <div className="text-sm font-medium mt-3 mb-2">Lost</div>
          <div className="space-y-2">{opps.filter(o=>o.status==='lost').map(o => (<div key={o.opportunity_id} className="border rounded p-2 text-xs">{(o.vendors||[]).join(', ')} • £{o.est_saving}</div>))}</div>
        </div>
      </div>

      <div className="mt-6 border rounded bg-white p-3" data-testid="vendors-table">
        <div className="flex items-center gap-2 mb-2">
          <input data-testid="vendors-search" className="border rounded px-2 py-1" value={q} onChange={(e)=>setQ(e.target.value)} placeholder="Search vendor name" />
          <select data-testid="vendors-category" className="border rounded px-2 py-1" value={category} onChange={(e)=>setCategory(e.target.value)}>
            <option value="">All</option>
            {cats.map(c=>(<option key={c} value={c}>{c}</option>))}
          </select>
          <select data-testid="vendors-shared" className="border rounded px-2 py-1" value={shared} onChange={(e)=>setShared(e.target.value)}>
            <option value="any">Shared: Any</option>
            <option value="true">Shared only</option>
            <option value="false">Not shared</option>
          </select>
          <button data-testid="vendors-apply" className="px-3 py-1 rounded bg-black text-white" onClick={loadVendors}>Apply</button>
        </div>
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left p-2">Vendor</th>
              <th className="text-left p-2">Category</th>
              <th className="text-left p-2">Companies</th>
              <th className="text-left p-2">Annual Spend</th>
              <th className="text-left p-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {vendors.map(v => (
              <tr key={v.vendor_id} className="border-t">
                <td className="p-2">{v.canonical_name}</td>
                <td className="p-2">{v.category}</td>
                <td className="p-2">{(v.companies||[]).map((c,i)=>(<span key={i} className="bg-gray-100 px-1 rounded mr-1 text-xs">{c}</span>))}</td>
                <td className="p-2">£{v.annual_spend}</td>
                <td className="p-2">
                  {canAdmin && <button className="text-xs border rounded px-2" onClick={async()=>{await api.post(`/vendors/${v.vendor_id}/alias`, { org_id: currentOrgId, add_names: [v.canonical_name]}); setMsg('Alias added');}}>Add alias</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {msg && <div className="text-sm mt-2">{msg}</div>}
    </div>
  );
}
