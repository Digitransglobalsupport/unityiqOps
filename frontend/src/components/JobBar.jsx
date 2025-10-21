import React, { useEffect, useRef, useState } from "react";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

const PHASE_LABEL = {
  queued: "Queued",
  discover: "Discovering data",
  ingest: "Ingesting",
  metrics: "Calculating metrics",
  alerts: "Checking alerts",
  done: "Complete",
  error: "Error",
};

export default function JobBar({ canRun }) {
  const { currentOrgId } = useOrg();
  const [job, setJob] = useState(null);
  const [polling, setPolling] = useState(false);
  const [errorsOpen, setErrorsOpen] = useState(false);
  const pollRef = useRef(null);

  const stopPoll = () => { if (pollRef.current) { clearTimeout(pollRef.current); pollRef.current = null; } setPolling(false); };
  const schedule = (fn, ms) => { pollRef.current = setTimeout(fn, ms); };

  const fetchLatest = async () => {
    if (!currentOrgId) return;
    try {
      const { data } = await api.get(`/sync-jobs/latest?org_id=${currentOrgId}&type=all_refresh`);
      if (data && data.job_id) {
        setJob(data);
        if (["done","error"].includes(data.phase)) stopPoll();
        else if (!polling) { setPolling(true); schedule(()=>pollJob(data.job_id), 1000); }
      } else {
        setJob(null);
      }
    } catch(e) { /* soft ignore */ }
  };

  const pollJob = async (jobId) => {
    if (document.hidden) return; // pause while hidden
    try {
      const { data } = await api.get(`/sync-jobs/${jobId}`);
      setJob(data);
      if (["done","error"].includes(data.phase)) { stopPoll(); }
      else { schedule(()=>pollJob(jobId), 3000); }
    } catch(e) { stopPoll(); /* job disappeared */ }
  };

  const runNow = async ()=>{
    if (!currentOrgId) return;
    try {
      const { data } = await api.post("/sync-jobs/start", { org_id: currentOrgId, type: "all_refresh" });
      setJob(data.job);
      if (data.status === "existing") {
        schedule(()=>pollJob(data.job.job_id), 1200);
      } else {
        schedule(()=>pollJob(data.job.job_id), 1200);
      }
    } catch(e) {
      const msg = e?.response?.data?.detail || e?.response?.data?.code || "Failed to start";
      alert(msg);
    }
  };

  // Visibility handling
  useEffect(() => {
    const onVis = () => {
      if (!job) return;
      if (document.hidden) {
        stopPoll();
      } else {
        // immediate fetch and resume cadence if active
        pollJob(job.job_id);
      }
    };
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, [job]);

  useEffect(()=>{ fetchLatest(); return ()=>stopPoll(); }, [currentOrgId]);

  const label = job ? (PHASE_LABEL[job.phase] || job.phase) : null;
  const pct = Math.round((job?.progress || 0) * 100);
  const eta = job?.eta_sec != null && job?.eta_sec > 0 ? `~${Math.floor(job.eta_sec/60)}:${String(job.eta_sec%60).padStart(2,'0')} remaining` : null;
  const errs = Array.isArray(job?.errors) ? job.errors.slice(0,5) : [];

  return (
    <div data-testid="job-bar" className="w-full">
      {!job && (
        <div className="flex items-center justify-between text-sm py-2">
          <div className="text-gray-600">Last sync: {/* TODO (spec): show relative time from finance data */}</div>
          {canRun && <button data-testid="job-run-now" onClick={runNow} className="px-3 py-1 bg-blue-600 text-white rounded text-sm">Run now</button>}
        </div>
      )}
      {job && (
        <div className="sticky top-0 z-10 bg-white border rounded p-3 mt-2">
          <div className="flex items-center justify-between">
            <div className="text-sm" data-testid="job-phase">{label}</div>
            {canRun && <button data-testid="job-run-now" onClick={runNow} className="px-2 py-1 bg-blue-600 text-white rounded text-xs">Run now</button>}
          </div>
          <div className="mt-2">
            <div className="w-full bg-gray-200 h-2 rounded">
              <div className="h-2 bg-green-500 rounded" style={{ width: `${pct}%`}} />
            </div>
            <div className="flex items-center justify-between text-xs text-gray-600 mt-1">
              <span data-testid="job-progress">{pct}%</span>
              {eta && <span data-testid="job-eta">{eta}</span>}
            </div>
          </div>
          <div className="mt-2">
            <button className="text-xs text-gray-700 underline" onClick={()=>setErrorsOpen(!errorsOpen)}>
              Errors ({errs.length})
            </button>
            {errorsOpen && (
              <div data-testid="job-errors-accordion" className="mt-1 space-y-1">
                {errs.map((e, idx)=> (
                  <div key={idx} className="text-xs text-red-600 truncate" title={e.message}>
                    <span className="px-1 py-0.5 bg-red-100 text-red-700 rounded mr-1">{e.phase}</span>
                    <span className="font-medium mr-1">{e.code}</span>
                    <span className="text-gray-700">{e.message}</span>
                    <span className="ml-2 text-gray-500">{(e.at||"").substring(11,16)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
