import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";
import { Toaster, toast } from "sonner";

export default function SpendIngest(){
  const { currentOrgId, role } = useOrg();
  const [spend, setSpend] = useState(null);
  const [saas, setSaas] = useState(null);
  const [preview, setPreview] = useState({ spend: [], saas: [] });
  const [loading, setLoading] = useState(false);

  const canAnalyst = ["ANALYST","ADMIN","OWNER"].includes(role||"");

  const readPreview = async (file) => {
    if (!file) return [];
    const text = await file.text();
    const [header, ...rows] = text.split(/\r?\n/).filter(Boolean);
    const cols = header.split(',');
    return rows.slice(0,10).map(r => {
      const vals = r.split(',');
      const obj = {}; cols.forEach((c,i)=> obj[c.trim()] = (vals[i]||'').trim());
      return obj;
    });
  };

  const onFile = async (type, file) => {
    if (type==='spend') setSpend(file);
    if (type==='saas') setSaas(file);
    const rows = await readPreview(file);
    setPreview(p => ({ ...p, [type]: rows }));
  };

  const submit = async () => {
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append('org_id', currentOrgId);
      if (spend) fd.append('spend', spend);
      if (saas) fd.append('saas', saas);
      const { data } = await api.post('/ingest/spend/csv', fd, { headers: { 'Content-Type': 'multipart/form-data' } });
      toast.success(`Ingested spend:${data.ingested.spend} saas:${data.ingested.saas}`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || 'Ingest failed');
    } finally { setLoading(false); }
  };

  const refresh = async () => {
    setLoading(true);
    try {
      const d = new Date();
      const to = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 0)).toISOString().slice(0,10);
      const from = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth()-3, 1)).toISOString().slice(0,10);
      await api.post('/ingest/spend/refresh', { org_id: currentOrgId, from, to, sources: ['csv'] });
      toast.success('Savings recomputed');
    } catch (e) {
      toast.error(e?.response?.data?.detail || 'Refresh failed');
    } finally { setLoading(false); }
  };

  return (
    <div className="max-w-4xl mx-auto p-6" data-testid="spend-upload">
      <Toaster richColors />
      <div className="text-xl font-semibold mb-2">Spend Ingest</div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="border rounded p-3">
          <div className="font-medium mb-2">spend.csv</div>
          <input type="file" accept=".csv" onChange={(e)=> onFile('spend', e.target.files?.[0]||null)} />
        </div>
        <div className="border rounded p-3">
          <div className="font-medium mb-2">saas.csv (optional)</div>
          <input type="file" accept=".csv" onChange={(e)=> onFile('saas', e.target.files?.[0]||null)} />
        </div>
      </div>

      <div className="mt-4" data-testid="spend-validate">
        <div className="text-sm font-medium mb-2">Preview (first 10 rows)</div>
        <div className="grid md:grid-cols-2 gap-4">
          {['spend','saas'].map(k => (
            <div key={k} className="border rounded p-2">
              <div className="text-xs text-gray-500 mb-1">{k}.csv</div>
              {preview[k].length>0 ? (
                <table className="w-full text-xs">
                  <thead><tr>{Object.keys(preview[k][0]).map(h=> <th key={h} className="text-left p-1">{h}</th>)}</tr></thead>
                  <tbody>{preview[k].map((r,i)=>(<tr key={i} className="border-t">{Object.values(r).map((v,j)=>(<td key={j} className="p-1">{v}</td>))}</tr>))}</tbody>
                </table>
              ) : <div className="text-xs text-gray-500">No file</div>}
            </div>
          ))}
        </div>
      </div>

      <div className="mt-4 flex gap-2">
        <button data-testid="spend-submit" disabled={!canAnalyst || loading} onClick={submit} className={`px-3 py-1 rounded ${canAnalyst? 'bg-black text-white':'bg-gray-300 text-gray-600'}`}>{loading? 'Uploading...':'Upload'}</button>
        <button data-testid="spend-refresh" disabled={!canAnalyst || loading} onClick={refresh} className={`px-3 py-1 rounded ${canAnalyst? 'bg-black text-white':'bg-gray-300 text-gray-600'}`}>{loading? 'Recomputing...':'Recalculate Savings'}</button>
        <a href="/dashboard/vendors" className="text-sm underline">View Vendors</a>
      </div>
    </div>
  );
}
