import React, { useEffect, useMemo, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function ChecklistPanel() {
  const { currentOrgId } = useOrg();
  const [items, setItems] = useState([]);
  const [tab, setTab] = useState("vendor_saving");
  const [suggestions, setSuggestions] = useState([]);
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true); setError("");
    try {
      const [{ data: open }, { data: m }, { data: sug }] = await Promise.all([
        api.get(`/checklist?org_id=${currentOrgId}&status=open`),
        api.get(`/orgs/${currentOrgId}/members`),
        api.post(`/checklist/suggest`),
      ]);
      setItems(open||[]);
      setMembers(m||[]);
      setSuggestions(sug?.suggestions||[]);
    } catch (e) { setError(e?.response?.data?.detail || "Failed to load checklist"); }
    finally { setLoading(false); }
  };

  useEffect(()=>{ if(currentOrgId) load(); }, [currentOrgId]);

  const filtered = useMemo(()=> items.filter(i=> i.type===tab), [items, tab]);

  const assign = async (itemId, owner_user_id) => {
    setItems(prev=> prev.map(i=> i.id===itemId? {...i, owner_user_id}: i));
    try { await api.patch(`/checklist/${itemId}`, { owner_user_id }); }
    catch { /* revert? */ }
  };
  const setDue = async (itemId, due_date) => {
    setItems(prev=> prev.map(i=> i.id===itemId? {...i, due_date}: i));
    try { await api.patch(`/checklist/${itemId}`, { due_date }); }
    catch { }
  };
  const markDone = async (itemId, checked) => {
    const status = checked? 'done' : 'open';
    setItems(prev=> prev.map(i=> i.id===itemId? {...i, status}: i));
    try { await api.patch(`/checklist/${itemId}`, { status }); }
    catch { }
  };
  const addTopSuggestions = async () => {
    try {
      const toCreate = suggestions.slice(0,10);
      if (toCreate.length) await api.post(`/checklist`, toCreate);
      await load();
    } catch {}
  };

  if (loading) return <div>Loading checklist…</div>;
  if (error) return <div className="text-red-600">{String(error)}</div>;

  return (
    <div className="border rounded bg-white p-3" data-testid="synergy-checklist">
      <div className="flex items-center justify-between mb-2">
        <div className="flex gap-2 text-sm">
          <button className={`px-2 py-1 rounded ${tab==='vendor_saving'?'bg-black text-white':'bg-gray-100'}`} onClick={()=>setTab('vendor_saving')}>Vendor Savings</button>
          <button className={`px-2 py-1 rounded ${tab==='cross_sell'?'bg-black text-white':'bg-gray-100'}`} onClick={()=>setTab('cross_sell')}>Cross-sell</button>
        </div>
        <button className="text-sm underline" onClick={addTopSuggestions}>Add top suggestions</button>
      </div>
      <table className="w-full text-sm">
        <thead className="bg-gray-50">
          <tr>
            <th className="text-left p-2">Title</th>
            <th className="text-left p-2">Owner</th>
            <th className="text-left p-2">Due</th>
            <th className="text-left p-2">Done</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map(it=> (
            <tr key={it.id} className="border-t">
              <td className="p-2">{it.title}</td>
              <td className="p-2">
                <select value={it.owner_user_id||''} onChange={(e)=> assign(it.id, e.target.value)} className="border rounded px-2 py-1">
                  <option value="">Unassigned</option>
                  {members.map(m=> (<option key={m.user_id} value={m.user_id}>{m.email || m.user_id}</option>))}
                </select>
              </td>
              <td className="p-2"><input type="date" value={it.due_date||''} onChange={(e)=> setDue(it.id, e.target.value)} className="border rounded px-2 py-1" /></td>
              <td className="p-2"><input type="checkbox" checked={it.status==='done'} onChange={(e)=> markDone(it.id, e.target.checked)} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
