import React, { useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function CsvIngest() {
  const { currentOrgId, role } = useOrg();
  const [pl, setPl] = useState(null);
  const [bs, setBs] = useState(null);
  const [ar, setAr] = useState(null);
  const [msg, setMsg] = useState("");
  const [preview, setPreview] = useState({ pl: [], bs: [], ar: [] });

  const canIngest = ["ANALYST","ADMIN","OWNER"].includes(role || "");

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
    if (type==='pl') setPl(file);
    if (type==='bs') setBs(file);
    if (type==='ar') setAr(file);
    const rows = await readPreview(file);
    setPreview(p => ({ ...p, [type]: rows }));
  };

  const ingest = async () => {
    try {
      const fd = new FormData();
      fd.append('org_id', currentOrgId);
      if (pl) fd.append('pl', pl);
      if (bs) fd.append('bs', bs);
      if (ar) fd.append('ar', ar);
      const { data } = await api.post("/ingest/finance/csv", fd, { headers: { 'Content-Type': 'multipart/form-data' } });
      setMsg(`CSV ingested: ${JSON.stringify(data.ingested)}${data.warnings?.length? ' • warnings present':''}`);
    } catch (e) {
      setMsg(e?.response?.data?.detail || "Ingest failed");
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6" data-testid="csv-ingest">
      <div className="text-xl font-semibold mb-2">CSV Ingest</div>
      <div className="text-sm text-gray-600 mb-4">Upload pl.csv, ar.csv and optionally bs.csv. We validate and compute KPIs.</div>

      <div className="grid md:grid-cols-3 gap-4">
        {[{key:'pl',label:'pl.csv'},{key:'ar',label:'ar.csv'},{key:'bs',label:'bs.csv (optional)'}].map(x => (
          <div key={x.key} className="border rounded p-3">
            <div className="text-sm font-medium mb-2">{x.label}</div>
            <input data-testid={`file-${x.key}`} type="file" accept=".csv" onChange={(e)=> onFile(x.key, e.target.files?.[0]||null)} />
            {preview[x.key].length>0 && (
              <table className="w-full text-xs mt-2">
                <thead><tr>{Object.keys(preview[x.key][0]).map(h=> <th key={h} className="text-left p-1">{h}</th>)}</tr></thead>
                <tbody>{preview[x.key].map((r,i)=>(
                  <tr key={i} className="border-t">{Object.values(r).map((v,j)=>(<td key={j} className="p-1">{v}</td>))}</tr>
                ))}</tbody>
              </table>
            )}
          </div>
        ))}
      </div>

      <div className="mt-4">
        <button data-testid="csv-ingest-button" disabled={!canIngest} className={`px-4 py-2 rounded ${canIngest? 'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={ingest}>Ingest</button>
        {msg && <div className="mt-2 text-sm">{msg}</div>}
      </div>
    </div>
  );
}
