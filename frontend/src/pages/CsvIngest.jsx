import React, { useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function CsvIngest() {
  const { currentOrgId, role } = useOrg();
  const [pl, setPl] = useState("");
  const [bs, setBs] = useState("");
  const [ar, setAr] = useState("");
  const [msg, setMsg] = useState("");

  const canIngest = ["ANALYST","ADMIN","OWNER"].includes(role || "");

  const ingest = async () => {
    try {
      const body = { org_id: currentOrgId, pl, bs, ar };
      await api.post("/ingest/finance/csv", body);
      setMsg("CSV ingested. Go to dashboard.");
    } catch (e) {
      setMsg(e?.response?.data?.detail || "Ingest failed");
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-6" data-testid="csv-ingest">
      <div className="text-xl font-semibold mb-2">CSV Ingest (Demo)</div>
      <div className="text-sm text-gray-600 mb-4">Paste CSV content for pl.csv, bs.csv (optional), ar.csv</div>
      <textarea className="w-full h-28 border rounded p-2 mb-2" placeholder="pl.csv content" value={pl} onChange={(e)=>setPl(e.target.value)} />
      <textarea className="w-full h-28 border rounded p-2 mb-2" placeholder="bs.csv content (optional)" value={bs} onChange={(e)=>setBs(e.target.value)} />
      <textarea className="w-full h-28 border rounded p-2 mb-2" placeholder="ar.csv content" value={ar} onChange={(e)=>setAr(e.target.value)} />
      <button data-testid="csv-ingest-button" disabled={!canIngest} className={`px-4 py-2 rounded ${canIngest? 'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={ingest}>Ingest</button>
      {msg && <div className="mt-2 text-sm">{msg}</div>}
    </div>
  );
}
