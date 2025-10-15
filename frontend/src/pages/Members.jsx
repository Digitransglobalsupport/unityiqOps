import React, { useEffect, useMemo, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

export default function Members() {
  const { currentOrgId, role } = useOrg();
  const [members, setMembers] = useState([]);
  const [email, setEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("VIEWER");
  const [message, setMessage] = useState(null);

  const isAdminPlus = useMemo(() => ["ADMIN", "OWNER"].includes(role), [role]);

  const fetchMembers = async () => {
    if (!currentOrgId) return;
    const { data } = await api.get(`/orgs/${currentOrgId}/members`);
    setMembers(data);
  };

  useEffect(() => {
    fetchMembers();
    // eslint-disable-next-line
  }, [currentOrgId]);

  const invite = async () => {
    try {
      await api.post(`/orgs/${currentOrgId}/invite`, { email, role: inviteRole });
      setMessage("Invitation sent");
      setEmail("");
      fetchMembers();
    } catch (e) {
      setMessage(e?.response?.data?.detail || "Invite failed");
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-6">
      <h1 className="text-2xl font-semibold mb-4" data-testid="members-title">Members</h1>

      <div className="mb-4 p-4 bg-gray-50 border rounded">
        <div data-testid="members-role" className="text-sm">Your role: <span className="font-medium">{role || '-'}</span></div>
      </div>

      <div className="mb-6 p-4 border rounded bg-white">
        <h2 className="font-medium mb-2">Invite Member</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <input data-testid="invite-email" className="border px-3 py-2 rounded" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="user@example.com" />
          <select data-testid="invite-role" className="border px-3 py-2 rounded" value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}>
            <option value="VIEWER">VIEWER</option>
            <option value="ANALYST">ANALYST</option>
            <option value="ADMIN">ADMIN</option>
          </select>
          <button data-testid="invite-submit-button" disabled={!isAdminPlus} onClick={invite} className={`px-4 rounded text-white ${isAdminPlus ? 'bg-black' : 'bg-gray-400 cursor-not-allowed'}`}>Send Invite</button>
        </div>
        {message && <div data-testid="members-message" className="text-sm text-gray-700 mt-2">{message}</div>}
      </div>

      <h2 className="text-lg font-semibold mb-2">Members</h2>
      <div className="border rounded bg-white">
        <table className="w-full text-sm" data-testid="members-table">
          <thead>
            <tr className="bg-gray-50">
              <th className="text-left p-2">Membership ID</th>
              <th className="text-left p-2">User ID</th>
              <th className="text-left p-2">Email (invited)</th>
              <th className="text-left p-2">Role</th>
              <th className="text-left p-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.membership_id} className="border-t">
                <td className="p-2">{m.membership_id}</td>
                <td className="p-2">{m.user_id || '-'}</td>
                <td className="p-2">{m.invited_email || '-'}</td>
                <td className="p-2">{m.role}</td>
                <td className="p-2">{m.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
