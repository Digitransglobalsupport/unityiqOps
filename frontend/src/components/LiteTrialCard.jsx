import React, { useState } from "react";
import api from "@/api/client";

export default function LiteTrialCard({ onUpgradeSuccess }) {
  const [upgrading, setUpgrading] = useState(false);
  const [error, setError] = useState("");

  const handleStartTrial = async () => {
    setUpgrading(true);
    setError("");

    try {
      const { data } = await api.post('/billing/start-lite-trial');
      
      // Track telemetry
      console.log('trial_trial_started', { channel: 'direct' });
      
      // Notify parent to refresh entitlements
      if (onUpgradeSuccess) {
        await onUpgradeSuccess(data);
      }
    } catch (e) {
      const detail = e?.response?.data?.detail;
      
      if (detail?.code === 'ERR_PLAN_ALREADY_ACTIVATED') {
        console.log('trial_card_hidden', { reason: 'plan_flip' });
        // Notify parent to refresh and hide card
        if (onUpgradeSuccess) {
          await onUpgradeSuccess();
        }
      } else {
        setError("Couldn't start trial right now. Please try again.");
        console.error('Trial start error:', e);
      }
    } finally {
      setUpgrading(false);
    }
  };

  return (
    <div 
      className="mb-4 p-4 bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200 rounded shadow-sm"
      data-testid="lite-trial-card"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <h3 className="font-semibold text-lg text-gray-900 mb-1">
            Start Lite Trial (Export & 1 connector)
          </h3>
          <ul className="text-sm text-gray-700 space-y-1 ml-4 list-disc">
            <li>PDF Snapshot export</li>
            <li>1 Xero connector</li>
            <li>Up to 3 companies</li>
          </ul>
          {error && (
            <div className="mt-2 text-sm text-red-600" role="alert">
              {error}
            </div>
          )}
        </div>
        <button
          onClick={handleStartTrial}
          disabled={upgrading}
          className="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors whitespace-nowrap focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2"
          data-testid="lite-trial-cta"
          aria-label="Start Lite Trial"
        >
          {upgrading ? (
            <span className="flex items-center gap-2">
              <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Starting...
            </span>
          ) : (
            'Start Lite Trial'
          )}
        </button>
      </div>
    </div>
  );
}
