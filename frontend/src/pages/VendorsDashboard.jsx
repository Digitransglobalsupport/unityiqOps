import React, { useEffect, useMemo, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

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

  const loadVendors = async () => {
    const { data } = await api.get(`/vendors/master?org_id=${currentOrgId}&q=${encodeURIComponent(q)}&category=${category}&shared=${shared}&limit=50`);
    setVendors(data.items||[]); setSummary(data.summary||null);
  };
  const loadOpps = async () => {
    const { data } = await api.get(`/opps/savings?org_id=${currentOrgId}&status=${status}&limit=50`);
    setOpps(data.items||[]); setOppSummary(data.summary||null);
  };
  const loadCats = async () => {
    const { data } = await api.get('/vendors/categories'); setCats(data.categories||[]);
  };
  useEffect(()=>{ if (currentOrgId){ loadVendors(); loadOpps(); loadCats(); } }, [currentOrgId, status]);

  const moveStatus = async (opp_id, ns) => {
    try { await api.post(`/opps/savings/${opp_id}/status`, { status: ns }); setMsg('Status updated'); loadOpps(); } catch(e){ setMsg('Update failed'); }
  };
  const assignOpp = async (opp_id, user_id) => {
    try { await api.post(`/opps/savings/${opp_id}/assign`, { owner_user_id: user_id }); setMsg('Assigned'); loadOpps(); } catch(e){ setMsg('Assign failed'); }
  };

  return (
    <div className="max-w-6xl mx-auto p-6" data-testid="vendors-dashboard">
      <div className="text-2xl font-semibold mb-4">Vendors</div>
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
