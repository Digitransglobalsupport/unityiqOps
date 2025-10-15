import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function Dashboard() {
  const { currentOrgId, role } = useOrg();
  const [orgs, setOrgs] = useState([]);
  const [orgName, setOrgName] = useState("");
  const [message, setMessage] = useState(null);

  const fetchOrgs = async () => {
    const { data } = await api.get("/orgs");
    setOrgs(data);
  };

  useEffect(() => {
    fetchOrgs();
  }, []);

  const createOrg = async () => {
    try {
      const { data } = await api.post("/orgs", { name: orgName || "My Org" });
      setMessage(`Created org ${data.name}`);
      setOrgName("");
      fetchOrgs();
    } catch (e) {
      setMessage(e?.response?.data?.detail || "Create org failed");
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-6">
      <h1 className="text-2xl font-semibold mb-4" data-testid="dashboard-title">Dashboard</h1>
      <div className="mb-6">
        <div className="flex gap-2">
          <input data-testid="create-org-name" className="border px-3 py-2 rounded w-full" value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="New org name" />
          <button data-testid="create-org-button" className="bg-black text-white px-4 rounded" onClick={createOrg}>Create Org</button>
        </div>
        {message && <div data-testid="dashboard-message" className="text-sm text-gray-700 mt-2">{message}</div>}
      </div>

      <h2 className="text-lg font-semibold mb-2">Your Orgs</h2>
      <ul className="space-y-2" data-testid="org-list">
        {orgs.map((o) => (
          <li key={o.org_id} className={`p-3 border rounded ${currentOrgId === o.org_id ? 'bg-green-50' : 'bg-white'}`}>
            <div className="flex justify-between items-center">
              <div>
                <div className="font-medium">{o.name}</div>
                <div className="text-xs text-gray-500">{o.org_id}</div>
              </div>
              <div className="text-xs text-gray-600">Role: {role || '-'}</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
