import React from "react";
import { useAuth } from "@/context/AuthContext";
import { useOrg } from "@/context/OrgContext";
import { Link, useNavigate } from "react-router-dom";
import api from "@/api/client";
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } from "@/components/ui/dropdown-menu";

export default function NavBar() {
  const { user, memberships, logout, isAuthenticated } = useAuth();
  const { currentOrgId, setCurrentOrgId, role } = useOrg();
  const navigate = useNavigate();

  return (
    <div className="w-full bg-gray-900 text-white flex items-center justify-between px-4 py-2">
      <div className="flex items-center gap-4">
        <button data-testid="nav-home-link" className="font-semibold" onClick={() => navigate("/")}>UnityOps</button>
        {isAuthenticated && (
          <>
            <Link data-testid="nav-members-link" to="/members" className="text-sm text-gray-300 hover:text-white">Members</Link>
            <Link data-testid="nav-dev-emails-link" to="/dev/emails" className="text-sm text-gray-300 hover:text-white">Dev Emails</Link>
            {(["ADMIN","OWNER"].includes(role||"")) && (
              <>
                <DropdownMenu>
                  <DropdownMenuTrigger className="text-sm text-gray-300 hover:text-white">Connections</DropdownMenuTrigger>
                  <DropdownMenuContent className="bg-white text-gray-900 p-1 rounded shadow">
                    <DropdownMenuItem onClick={async ()=>{ try { const { data } = await api.post('/connections/xero/oauth/start', { org_id: currentOrgId }); window.location.href = data.auth_url; } catch(e) { alert(e?.response?.data?.detail?.code || e?.response?.data?.detail || 'Failed to start Xero'); }}}>Connect to Xero</DropdownMenuItem>
                    <DropdownMenuItem onClick={()=>{ window.location.href = '/connections'; }}>Manage connections…</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
                <Link data-testid="nav-settings-link" to="/settings" className="text-sm text-gray-300 hover:text-white">Settings</Link>
              </>
            )}
          </>
        )}
      </div>
      <div className="flex items-center gap-3">
        {!isAuthenticated ? (
          <div className="flex items-center gap-3">
            <Link to="/login" className="text-sm text-gray-300 hover:text-white">Log in</Link>
            <Link to="/signup" className="text-sm bg-white text-gray-900 px-2 py-1 rounded">Sign up</Link>
          </div>
        ) : (
          <>
            {/* When verified and orgless, show Create organisation CTA instead of switcher */}
            {(user?.email_verified && !currentOrgId && memberships.length === 0) ? (
              <Link to="/onboarding" data-testid="create-org-nav" className="text-sm bg-white text-gray-900 px-2 py-1 rounded">Create organisation</Link>
            ) : (
              <select
                data-testid="org-switcher"
                className="bg-gray-800 text-white text-sm px-2 py-1 rounded"
                value={currentOrgId || (memberships[0]?.org_id || "")}
                onChange={(e) => setCurrentOrgId(e.target.value)}
              >
                {memberships.map((m) => (
                  <option key={m.org_id} value={m.org_id}>{m.org_id} • {m.role}</option>
                ))}
              </select>
            )}
            <span data-testid="user-email" className="text-sm text-gray-300">{user?.email}</span>
            <span data-testid="user-role" className="text-xs bg-gray-800 px-2 py-1 rounded">{role || "-"}</span>
            <button data-testid="logout-button" onClick={logout} className="text-sm text-red-300 hover:text-red-400">Logout</button>
          </>
        )}
      </div>
    </div>
  );
}
