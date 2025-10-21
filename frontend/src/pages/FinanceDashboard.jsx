import React, { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";

import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";
import DataHealthPill from "@/components/DataHealthPill";
import ChecklistPanel from "@/components/ChecklistPanel";
import JobBar from "@/components/JobBar";
import LiteTrialInline from "@/components/LiteTrialInline";

export default function FinanceDashboard() {
  const { currentOrgId, role } = useOrg();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [entitlements, setEntitlements] = useState(null);
  const [vendorSummary, setVendorSummary] = useState(null);
  const [showScoreDetails, setShowScoreDetails] = useState(false);
  const canAdmin = ["OWNER","ADMIN"].includes(role||"");

  const loadEntitlements = useCallback(async () => {
    if (!currentOrgId) return;
    try {
      const { data } = await api.get('/billing/entitlements');
      setEntitlements(data);
    } catch(e) {
      console.error('Failed to load entitlements', e);
    }
  }, [currentOrgId]);

  if (!currentOrgId) {
    return (
      <div className="max-w-3xl mx-auto p-6" data-testid="orgless-prompt">
        <h1 className="text-2xl font-semibold mb-2">Finance</h1>
        <div className="border rounded bg-white p-6">
          <div className="text-base font-medium mb-1">Let’s connect your first company</div>
          <div className="text-sm text-gray-600 mb-4">Create or select an organisation to begin.</div>
          <div className="flex items-center gap-3">
            <button className="bg-black text-white px-4 py-2 rounded" onClick={()=> navigate('/onboarding')} data-testid="go-to-onboarding">Go to Onboarding</button>
            <a href="/about" className="text-sm underline text-gray-700">Learn more</a>
          </div>
        </div>
      </div>
    );
  }

  const canRun = role === "OWNER" || role === "ADMIN" || role === "ANALYST";

  const load = async () => {
    setLoading(true); setError("");
    try { 
      const { data } = await api.get(`/dashboard/finance?org_id=${currentOrgId}`); 
      setData(data); 
      
      // Load vendor summary
      try {
        const vendorRes = await api.get(`/vendors/savings-opps?org_id=${currentOrgId}&status=open&limit=100`);
        const opps = vendorRes.data.opportunities || [];
        const totalSavings = opps.reduce((sum, o) => sum + (o.est_saving || 0), 0);
        setVendorSummary({
          shared_vendors_count: new Set(opps.flatMap(o => o.vendors || [])).size,
          total_savings: totalSavings,
          opps_count: opps.length
        });
      } catch (e) {
        console.error('Failed to load vendor summary', e);
      }
    }
    catch (e) { setError(e?.response?.data?.detail || "Failed to load"); }
    finally { setLoading(false); }
  };

  useEffect(()=>{ 
    if(currentOrgId) {
      load();
      loadEntitlements();
    }
  }, [currentOrgId, loadEntitlements]);

  const reconnect = async ()=>{
    try { const { data } = await api.post("/connections/xero/oauth/start", { org_id: currentOrgId }); window.location.href = data.auth_url; }
    catch(e){ alert(e?.response?.data?.detail || "Failed to start OAuth"); }
  };

  const handleUpgradeSuccess = async (data) => {
    // Reload entitlements after upgrade
    await loadEntitlements();
    await load();
  };

  // Check if we should show inline trial CTA
  const showInlineCTA = entitlements && 
                        canAdmin && 
                        entitlements.plan?.tier === 'FREE' && 
                        entitlements.limits?.connectors === 0;

  if (loading) return <div className="p-6">Loading...</div>;
  if (error) return <div className="p-6 text-red-600">{String(error)}</div>;

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-4" data-testid="finance-dashboard">
      {/* Header strip */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold">Finance</h1>
          {showInlineCTA && <LiteTrialInline onUpgradeSuccess={handleUpgradeSuccess} />}
        </div>
        <DataHealthPill connection={data?.connection} onReconnect={reconnect} onRetry={load} />
      </div>

      {/* Job Monitor */}
      <JobBar canRun={canRun} />

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-4 gap-3">
        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-1 text-gray-700">Revenue</div>
          <div className="text-2xl font-bold">
            {data?.kpis?.revenue ? `£${Math.round(data.kpis.revenue).toLocaleString()}` : "-"}
          </div>
          <div className="text-xs text-gray-500 mt-1">{data?.period?.from || 'Latest'}</div>
        </div>
        
        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-1 text-gray-700">Gross Margin %</div>
          <div className="text-2xl font-bold">
            {data?.kpis?.gm_pct ? `${data.kpis.gm_pct.toFixed(1)}%` : "-"}
          </div>
          <div className="text-xs text-gray-500 mt-1">Latest period</div>
        </div>
        
        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-1 text-gray-700">Opex</div>
          <div className="text-2xl font-bold">
            {data?.kpis?.opex ? `£${Math.round(data.kpis.opex).toLocaleString()}` : "-"}
          </div>
          <div className="text-xs text-gray-500 mt-1">Latest period</div>
        </div>
        
        <div className="border rounded bg-white p-3">
          <div className="text-sm font-medium mb-1 text-gray-700">DSO (days)</div>
          <div className="text-2xl font-bold">{data?.kpis?.dso_days ?? "-"}</div>
          <div className="text-xs text-gray-500 mt-1">Days sales outstanding</div>
        </div>
      </div>

      {/* Synergy Score Block */}
      {data?.score && (
        <div className="border rounded bg-gradient-to-r from-blue-50 to-indigo-50 p-4">
          <div className="flex items-center justify-between mb-2">
            <div>
              <div className="text-sm font-medium text-gray-700">Synergy Score</div>
              <div className="text-3xl font-bold text-indigo-600">{data.score.s_fin || 72}</div>
            </div>
            <button
              onClick={() => setShowScoreDetails(!showScoreDetails)}
              className="text-sm text-indigo-600 hover:text-indigo-800 underline"
            >
              {showScoreDetails ? 'Hide details' : 'Why this score?'}
            </button>
          </div>
          
          {showScoreDetails && data.score.drivers && (
            <div className="mt-3 pt-3 border-t border-indigo-200 text-sm space-y-2">
              <div className="font-medium text-gray-700">Score Drivers:</div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {data.score.drivers.gm_delta_pct !== undefined && (
                  <div className="bg-white p-2 rounded">
                    <span className="text-gray-600">GM Delta:</span>{' '}
                    <span className="font-medium">{data.score.drivers.gm_delta_pct}%</span>
                  </div>
                )}
                {data.score.drivers.opex_delta_pct !== undefined && (
                  <div className="bg-white p-2 rounded">
                    <span className="text-gray-600">Opex Delta:</span>{' '}
                    <span className="font-medium">{data.score.drivers.opex_delta_pct}%</span>
                  </div>
                )}
                {data.score.drivers.dso_delta_days !== undefined && (
                  <div className="bg-white p-2 rounded">
                    <span className="text-gray-600">DSO Delta:</span>{' '}
                    <span className="font-medium">{data.score.drivers.dso_delta_days} days</span>
                  </div>
                )}
              </div>
              {data.score.drivers.notes && data.score.drivers.notes.length > 0 && (
                <div className="text-xs text-gray-600 mt-2">
                  {data.score.drivers.notes.map((note, i) => (
                    <div key={i}>• {note}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Customer Lens Summary */}
      {data?.customer_lens && (
        <div className="border rounded bg-white p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold">Customer Lens</h3>
            <button
              onClick={() => navigate('/dashboard/customers')}
              className="text-sm text-blue-600 hover:text-blue-800 underline"
            >
              View Customers →
            </button>
          </div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <div className="text-gray-600">Shared Accounts</div>
              <div className="text-xl font-bold text-gray-900">{data.customer_lens.shared_accounts || 0}</div>
            </div>
            <div>
              <div className="text-gray-600">Cross-sell Opportunities</div>
              <div className="text-xl font-bold text-gray-900">{data.customer_lens.cross_sell_count || 0}</div>
            </div>
            <div>
              <div className="text-gray-600">Expected Value</div>
              <div className="text-xl font-bold text-green-600">
                £{(data.customer_lens.cross_sell_value || 0).toLocaleString()}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Vendor Lens Summary */}
      {vendorSummary && (
        <div className="border rounded bg-white p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold">Vendors Lens</h3>
            <button
              onClick={() => navigate('/dashboard/vendors')}
              className="text-sm text-blue-600 hover:text-blue-800 underline"
            >
              View Vendors →
            </button>
          </div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <div className="text-gray-600">Shared Vendors</div>
              <div className="text-xl font-bold text-gray-900">{vendorSummary.shared_vendors_count || 0}</div>
            </div>
            <div>
              <div className="text-gray-600">Savings Opportunities</div>
              <div className="text-xl font-bold text-gray-900">{vendorSummary.opps_count || 0}</div>
            </div>
            <div>
              <div className="text-gray-600">Est. Savings Pipeline</div>
              <div className="text-xl font-bold text-orange-600">
                £{(vendorSummary.total_savings || 0).toLocaleString()}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Action Plan / Checklist */}
      <ChecklistPanel />
    </div>
  );
}
