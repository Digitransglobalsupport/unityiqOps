import React, { useEffect, useState } from "react";
import api from "@/api/client";
import { useAuth } from "@/context/AuthContext";
import ErrorBanner from "@/components/ErrorBanner";

export default function Dashboard(){
  const { isAuthenticated, user } = useAuth();
  const [orgs, setOrgs] = useState([]);
  const [error, setError] = useState("");

  useEffect(()=>{
    if (!isAuthenticated || !user?.email_verified) return;
    let mounted = true;
    const load = async ()=>{
      try { const { data } = await api.get("/orgs"); if(mounted) setOrgs(data); }
      catch(e){ if(mounted) setError("Backend temporarily unavailable. Retrying…"); setTimeout(load, 2500); }
    };
    load();
    return ()=> { mounted=false; };
  }, [isAuthenticated, user?.email_verified]);

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-2xl font-semibold mb-4">Your organisations</h1>
      {(!isAuthenticated || !user?.email_verified) && <div className="text-sm text-gray-600">Please log in and verify your email.</div>}
      <ul className="list-disc ml-6">
        {orgs.map(o=> (<li key={o.org_id}>{o.name}</li>))}
      </ul>
      <ErrorBanner message={error} onRetry={()=> window.location.reload()} />
    </div>
  );
}
