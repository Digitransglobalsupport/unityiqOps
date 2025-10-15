import React, { useEffect, useState } from "react";
import api from "@/api/client";

export default function DevEmails() {
  const [emails, setEmails] = useState([]);

  const fetchEmails = async () => {
    const { data } = await api.get("/dev/emails");
    setEmails(data);
  };

  useEffect(() => {
    fetchEmails();
  }, []);

  const callAction = async (e) => {
    try {
      if (e.action === 'verify_email') {
        await api.post('/auth/verify-email', { token: e.token });
        alert('Email verified');
      } else if (e.action === 'password_reset') {
        const newPass = prompt('Enter new password');
        if (!newPass) return;
        await api.post('/auth/reset', { token: e.token, new_password: newPass });
        alert('Password reset');
      } else if (e.action === 'invite') {
        await api.post('/invites/accept', { token: e.token });
        alert('Invite accepted');
      }
      fetchEmails();
    } catch (err) {
      alert(err?.response?.data?.detail || 'Action failed');
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold" data-testid="dev-emails-title">Dev Emails</h1>
        <button data-testid="refresh-dev-emails" onClick={fetchEmails} className="bg-black text-white px-3 py-1 rounded">Refresh</button>
      </div>
      <div className="space-y-3">
        {emails.map((e) => (
          <div key={e.email_id} className="border rounded p-3 bg-white" data-testid="dev-email-item">
            <div className="text-sm text-gray-500">To: {e.to}</div>
            <div className="font-medium">{e.subject}</div>
            <div className="text-xs text-gray-600">Action: {e.action}</div>
            {e.url_path && (
              <div className="mt-2 flex items-center gap-2">
                <code data-testid="dev-email-url" className="text-xs bg-gray-100 p-1 rounded">{e.url_path}</code>
                <button data-testid="dev-email-action-button" onClick={() => callAction(e)} className="text-xs bg-blue-600 text-white px-2 py-1 rounded">Run</button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
