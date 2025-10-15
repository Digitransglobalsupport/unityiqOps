import React, { useEffect, useState } from "react";
import { useOrg } from "@/context/OrgContext";
import api from "@/api/client";

export default function CrmIngest() {
  const { currentOrgId, role } = useOrg();
  const [contacts, setContacts] = useState(null);
  const [companies, setCompanies] = useState(null);
  const [deals, setDeals] = useState(null);
  const [msg, setMsg] = useState("");
  const [dash, setDash] = useState(null);

  const canAnalyst = ["ANALYST","ADMIN","OWNER"].includes(role||"");

  const mockIngest = async () => {
    try {
      await api.post('/crm/hubspot/mock/ingest', {});
      setMsg('Mock CRM data ingested');
    } catch (e) { setMsg(e?.response?.data?.detail || 'Failed'); }
  };

  const uploadCsv = async () => {
    try {
      const fd = new FormData();
      fd.append('org_id', currentOrgId);
      if (contacts) fd.append('contacts', contacts);
      if (companies) fd.append('companies', companies);
      if (deals) fd.append('deals', deals);
      const { data } = await api.post('/crm/csv/ingest', fd, { headers: { 'Content-Type': 'multipart/form-data' } });
      setMsg(`CSV uploaded: ${JSON.stringify(data.counts)}`);
    } catch (e) { setMsg(e?.response?.data?.detail || 'Failed'); }
  };

  const runDedupe = async () => {
    try { await api.post('/crm/dedupe/run'); setMsg('Dedupe complete'); } catch (e) { setMsg('Dedupe failed'); }
  };
  const runOpps = async () => {
    try { await api.post('/crm/cross-sell/run'); setMsg('Cross-sell computed'); } catch (e) { setMsg('Cross-sell failed'); }
  };
  const loadDashboard = async () => {
    try { const { data } = await api.get(`/crm/dashboard?org_id=${currentOrgId}`); setDash(data); } catch (e) { setMsg('Dashboard load failed'); }
  };

  useEffect(()=>{ if (currentOrgId) loadDashboard(); }, [currentOrgId]);

  return (
    <div className="max-w-5xl mx-auto p-6" data-testid="crm-ingest">
      <div className="text-xl font-semibold mb-3">CRM Ingest</div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="border rounded p-3">
          <div className="font-medium mb-2">Mock HubSpot</div>
          <button data-testid="crm-mock-button" disabled={!canAnalyst} className={`px-3 py-1 rounded ${canAnalyst?'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={mockIngest}>Ingest Mock</button>
        </div>
        <div className="border rounded p-3">
          <div className="font-medium mb-2">CSV Upload</div>
          <input data-testid="crm-file-contacts" type="file" accept=".csv" onChange={(e)=> setContacts(e.target.files?.[0]||null)} />
          <input data-testid="crm-file-companies" type="file" accept=".csv" onChange={(e)=> setCompanies(e.target.files?.[0]||null)} className="mt-2" />
          <input data-testid="crm-file-deals" type="file" accept=".csv" onChange={(e)=> setDeals(e.target.files?.[0]||null)} className="mt-2" />
          <button data-testid="crm-upload-button" disabled={!canAnalyst} className={`mt-2 px-3 py-1 rounded ${canAnalyst?'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={uploadCsv}>Upload</button>
        </div>
      </div>

      <div className="mt-4 flex gap-2">
        <button data-testid="crm-dedupe-button" disabled={!canAnalyst} className={`px-3 py-1 rounded ${canAnalyst?'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={runDedupe}>Run Dedupe</button>
        <button data-testid="crm-opps-button" disabled={!canAnalyst} className={`px-3 py-1 rounded ${canAnalyst?'bg-black text-white':'bg-gray-300 text-gray-600'}`} onClick={runOpps}>Compute Opps</button>
        <button data-testid="crm-dashboard-button" className="px-3 py-1 rounded border" onClick={loadDashboard}>Refresh View</button>
      </div>
      {msg && <div className="text-sm mt-2">{msg}</div>}

      {dash && (
        <div className="mt-4 border rounded p-3 bg-white">
          <div className="text-sm">Shared accounts: {dash.kpis?.shared_accounts}</div>
          <div className="text-sm">Cross-sell value: {dash.kpis?.cross_sell_value}</div>
          <div className="mt-2">
            <div className="font-medium">Opportunities</div>
            <ul className="list-disc ml-6 text-sm">
              {(dash.opps||[]).map((o,i)=>(<li key={i}>{o.rationale} • EV £{o.expected_value}</li>))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
