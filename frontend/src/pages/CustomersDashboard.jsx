import React, { useEffect, useMemo, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function CustomersDashboard() {
  const { currentOrgId, role } = useOrg();
  const [q, setQ] = useState("");
  const [minConf, setMinConf] = useState(0.7);
  const [cursor, setCursor] = useState(null);
  const [masters, setMasters] = useState([]);
  const [stats, setStats] = useState(null);
  const [opps, setOpps] = useState([]);
  const [statusFilter, setStatusFilter] = useState("open");
  const [msg, setMsg] = useState("");
  const [loading, setLoading] = useState(false);

  const canAnalyst = ["ANALYST","ADMIN","OWNER"].includes(role||"");
  const canAdmin = ["ADMIN","OWNER"].includes(role||"");

  const loadMasters = async (c=null) => {
    setLoading(true); setMsg("");
    try {
      const { data } = await api.get(`/customers/master?org_id=${currentOrgId}&q=${encodeURIComponent(q)}&min_conf=${minConf}&limit=50${c?`&cursor=${c}`:''}`);
      setMasters(data.items || []);
      setStats(data.stats || null);
      setCursor(data.cursor || null);
    } catch(e) { setMsg(e?.response?.data?.detail || 'Failed to load'); }
    finally { setLoading(false); }
  };

  const loadOpps = async () => {
    try { const { data } = await api.get(`/opps/cross-sell?org_id=${currentOrgId}&status=${statusFilter}&limit=50`); setOpps(data.items || []);} catch(e){}
  };

  useEffect(()=>{ if(currentOrgId){ loadMasters(); loadOpps(); } }, [currentOrgId, statusFilter]);

  const review = async (pair_id, decision, master_id) => {
    try {
      await api.post('/crm/dedupe/review', { org_id: currentOrgId, decisions: [{ pair_id, decision, master_id }]});
      setMsg('Review applied');
      loadMasters();
      loadOpps();
    } catch (e) { setMsg('Review failed'); }
  };

  const changeOpp = async (opp_id, status) => {
    try { await api.post(`/opps/${opp_id}/status`, { status }); setMsg('Status updated'); loadOpps(); } catch(e){ setMsg('Status update failed'); }
  };

  return (
    <div className="max-w-6xl mx-auto p-6" data-testid="customers-dashboard">
      <div className="flex items-center justify-between mb-4">
        <div className="text-2xl font-semibold">Customers</div>
        <div className="text-sm text-gray-600">{stats && <>Masters: <b>{stats.masters}</b> • Shared: <b>{stats.shared_accounts}</b> • Avg conf: <b>{stats.avg_conf}</b></>}</div>
      </div>

      <div className="mb-4 flex items-center gap-3">
        <input data-testid="cust-search" className="border rounded px-3 py-1" placeholder="Search name/email/domain" value={q} onChange={(e)=>setQ(e.target.value)} />
        <label className="text-sm">Min confidence</label>
        <input data-testid="cust-conf" type="number" step="0.05" min="0" max="1" className="border rounded px-2 py-1 w-24" value={minConf} onChange={(e)=>setMinConf(parseFloat(e.target.value||'0.7'))} />
        <button data-testid="cust-apply" className="px-3 py-1 rounded bg-black text-white" onClick={()=>loadMasters()}>Apply</button>
      </div>

      {msg && <div className="text-sm mb-2">{msg}</div>}

      <div className="grid md:grid-cols-3 gap-4">
        <div className="md:col-span-2 border rounded bg-white p-3">
          <div className="text-sm font-medium mb-2">Master Records</div>
          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left p-2">Name</th>
                <th className="text-left p-2">Confidence</th>
                <th className="text-left p-2">Companies</th>
                <th className="text-left p-2">Emails</th>
                <th className="text-left p-2">Domains</th>
              </tr>
            </thead>
            <tbody>
              {masters.map(m => (
                <tr key={m.master_id} className="border-t">
                  <td className="p-2">
                    <div className="font-medium">{m.canonical_name}</div>
                    <div className="text-xs text-gray-500">{m.review_state === 'needs_review' ? <span className="bg-yellow-50 text-yellow-800 px-1 rounded">Needs review (0.7–0.85)</span> : <span className="bg-green-50 text-green-800 px-1 rounded">Auto-matched (≥0.85)</span>}</div>
                  </td>
                  <td className="p-2">{m.confidence}</td>
                  <td className="p-2">{(m.companies||[]).map(c=>(<span key={c} className="text-xs bg-gray-100 px-1.5 py-0.5 rounded mr-1">{c}</span>))}</td>
                  <td className="p-2">{(m.emails||[]).slice(0,1).join(', ')}</td>
                  <td className="p-2">{(m.domains||[]).slice(0,1).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {cursor && <button data-testid="cust-next" className="mt-2 text-sm underline" onClick={()=>loadMasters(cursor)}>Next</button>}
        </div>
        <div className="border rounded bg-white p-3">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium">Opportunities</div>
            <select data-testid="opp-status-filter" className="text-xs border rounded px-2 py-1" value={statusFilter} onChange={(e)=>setStatusFilter(e.target.value)}>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="won">Won</option>
              <option value="lost">Lost</option>
            </select>
          </div>
          <ul className="mt-2 space-y-2">
            {opps.map(o => (
              <li key={o.opportunity_id} className="border rounded p-2">
                <div className="text-sm font-medium">{o.name || o.master_id} • EV £{o.expected_value}</div>
                <div className="text-xs text-gray-500">{(o.companies||[]).map((c,i)=>(<span key={i} className="bg-gray-100 px-1 rounded mr-1">{c}</span>))}</div>
                <div className="text-xs mt-1">NBA: {o.next_best_action}</div>
                {canAdmin && (
                  <div className="mt-2 flex gap-2">
                    {['contacted','in_progress','won','lost'].map(s => (
                      <button key={s} data-testid={`opp-${o.opportunity_id}-${s}`} className="text-xs border rounded px-2 py-0.5" onClick={()=>changeOpp(o.opportunity_id, s)}>{s}</button>
                    ))}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="mt-6 p-3 bg-gray-50 border rounded text-xs text-gray-600">
        Legend: <span className="bg-yellow-50 text-yellow-800 px-1 rounded">Needs review (0.7–0.85)</span> • <span className="bg-green-50 text-green-800 px-1 rounded">Auto-matched (≥0.85)</span>
        <div className="mt-1">No data? <a className="underline" href="/ingest/crm">Ingest CRM</a></div>
      </div>
    </div>
  );
}
