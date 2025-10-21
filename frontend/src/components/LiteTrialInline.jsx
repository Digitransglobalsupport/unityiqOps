import React, { useState } from "react";
import api from "@/api/client";

export default function LiteTrialInline({ onUpgradeSuccess }) {
  const [upgrading, setUpgrading] = useState(false);

  const handleStartTrial = async () => {
    setUpgrading(true);

    try {
      const { data } = await api.post('/billing/start-lite-trial');
      console.log('trial_trial_started', { channel: 'direct', source: 'finance_inline' });
      
      if (onUpgradeSuccess) {
        await onUpgradeSuccess(data);
      }
    } catch (e) {
      const detail = e?.response?.data?.detail;
      if (detail?.code === 'ERR_PLAN_ALREADY_ACTIVATED' && onUpgradeSuccess) {
        await onUpgradeSuccess();
      }
    } finally {
      setUpgrading(false);
    }
  };

  return (
    <button
      onClick={handleStartTrial}
      disabled={upgrading}
      className="px-3 py-1 text-sm bg-purple-600 text-white rounded hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-1"
      data-testid="lite-trial-inline"
      aria-label="Start Lite Trial"
    >
      {upgrading ? 'Starting...' : 'Start Lite Trial'}
    </button>
  );
}
