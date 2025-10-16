import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function Settings() {
  const { role } = useOrg();
  const [s, setS] = useState({ volume_pct: 8, saas_pct: 15, tail_threshold: 300 });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState("");
  const canAdmin = ["ADMIN","OWNER"].includes(role||"");

  const load = async () => {
    setLoading(true); setMsg("");
    try { const { data } = await api.get("/orgs/settings"); setS(data.savings || s); } catch(e) {}
    finally { setLoading(false); }
  };

  useEffect(()=>{ load(); },[]);

  const save = async () => {
    if (!canAdmin) return;
    setSaving(true); setMsg("");
    try { await api.put("/orgs/settings", { savings: s }); setMsg("Saved"); }
    catch(e){ setMsg(e?.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  if (!canAdmin) return <div className="max-w-3xl mx-auto p-6">You need Admin or Owner role to edit settings.</div>;
  if (loading) return <div className="max-w-3xl mx-auto p-6">Loading...</div>;

  return (
    <div className="max-w-3xl mx-auto p-6" data-testid="settings-page">
      <h1 className="text-2xl font-semibold mb-4">Settings</h1>
      <div className="border rounded bg-white p-4 space-y-4">
        <div>
          <div className="text-sm font-medium">Savings assumptions</div>
          <div className="text-xs text-gray-600">These affect Vendor savings heuristics and Snapshot export footer.</div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <label className="text-sm">Volume %
            <input type="number" min={0} max={50} className="mt-1 w-full border rounded px-2 py-1" value={s.volume_pct}
              onChange={(e)=> setS(v=> ({...v, volume_pct: Math.max(0, Math.min(50, parseInt(e.target.value||0)))}))} />
          </label>
          <label className="text-sm">SaaS %
            <input type="number" min={0} max={50} className="mt-1 w-full border rounded px-2 py-1" value={s.saas_pct}
              onChange={(e)=> setS(v=> ({...v, saas_pct: Math.max(0, Math.min(50, parseInt(e.target.value||0)))}))} />
          </label>
          <label className="text-sm">Tail threshold (£)
            <input type="number" min={0} max={5000} className="mt-1 w-full border rounded px-2 py-1" value={s.tail_threshold}
              onChange={(e)=> setS(v=> ({...v, tail_threshold: Math.max(0, Math.min(5000, parseInt(e.target.value||0)))}))} />
          </label>
        </div>
        <div className="flex items-center gap-2">
          <button data-testid="settings-save" className="px-3 py-1 rounded bg-black text-white" onClick={save} disabled={saving}>{saving? 'Saving...' : 'Save'}</button>
          {msg && <div className="text-sm">{msg}</div>}
        </div>
        <div className="text-xs text-gray-500">Tip: You can dismiss the Snapshot banner anytime here.</div>
      </div>
    </div>
  );
}
