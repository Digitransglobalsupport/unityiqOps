import React from "react";

export default function InlineErrorBanner({ visible, countdownSec, onRetryNow, onDismiss }) {
  if (!visible) return null;
  const secs = Math.max(0, Math.round(countdownSec || 0));
  return (
    <div className="mb-3 border border-red-200 bg-red-50 text-red-800 rounded p-3" data-testid="inline-error-banner">
      <div className="text-sm font-medium">Temporary issue talking to the server. We’ll retry automatically.</div>
      <div className="mt-1 text-xs text-red-700" data-testid="inline-error-countdown">Retrying in {secs}s…</div>
      <div className="mt-2 flex items-center gap-3">
        <button className="text-xs px-2 py-1 bg-red-600 text-white rounded" onClick={onRetryNow} data-testid="inline-error-retry">Retry now</button>
        <button className="text-xs text-red-700 underline" onClick={onDismiss} data-testid="inline-error-dismiss">Dismiss</button>
      </div>
    </div>
  );
}
