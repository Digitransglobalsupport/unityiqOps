import React from "react";
import api from "@/api/client";

export default function DataHealthPill({ connection, onReconnect, onRetry }) {
  if (!connection) return null;
  const { provider, connected, last_sync_at, error } = connection;
  const age = (()=>{
    if (!last_sync_at) return null;
    try {
      const t = new Date(last_sync_at).getTime();
      const mins = Math.floor((Date.now() - t)/60000);
      if (mins < 60) return `${mins}m`;
      const h = Math.floor(mins/60); if (h<24) return `${h}h`;
      const d = Math.floor(h/24); return `${d}d`;
    } catch { return null; }
  })();
  if (error) {
    return (
      <div className="inline-flex items-center gap-2 px-2 py-1 rounded bg-yellow-100 text-yellow-900 text-xs">
        {provider}: {error.message || error.code || 'Issue detected'}
        <button className="underline" onClick={onReconnect}>Reconnect</button>
        <button className="underline" onClick={onRetry}>Retry</button>
      </div>
    );
  }
  if (connected) {
    return (
      <div className="inline-flex items-center gap-2 px-2 py-1 rounded bg-green-100 text-green-900 text-xs">
        {provider}: Connected{age? ` · Synced ${age} ago`: ''}
        <button className="underline" onClick={onRetry}>Refresh now</button>
      </div>
    );
  }
  return null;
}
