import React from "react";

export default function LiteTrialSkeleton() {
  return (
    <div 
      className="mb-4 p-4 bg-gray-50 border border-gray-200 rounded shadow-sm animate-pulse"
      data-testid="lite-trial-skeleton"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 space-y-2">
          <div className="h-5 bg-gray-300 rounded w-3/4"></div>
          <div className="space-y-1 ml-4">
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
            <div className="h-4 bg-gray-200 rounded w-2/3"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
          </div>
        </div>
        <div className="h-10 w-32 bg-gray-300 rounded"></div>
      </div>
    </div>
  );
}
