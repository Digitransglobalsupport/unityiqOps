import React from "react";

export default function ErrorBanner({ message, onRetry }) {
  if (!message) return null;
  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 max-w-lg w-[90%] bg-red-600 text-white text-sm px-3 py-2 rounded shadow">
      <div className="flex items-center justify-between gap-3">
        <span>{message}</span>
        {onRetry && <button className="underline" onClick={onRetry}>Retry</button>}
      </div>
    </div>
  );
}
