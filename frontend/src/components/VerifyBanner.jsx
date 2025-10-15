import React from "react";
import { Link } from "react-router-dom";

export default function VerifyBanner({ show }) {
  if (!show) return null;
  return (
    <div data-testid="verify-banner" className="w-full bg-yellow-50 border-b border-yellow-200 text-yellow-900">
      <div className="max-w-5xl mx-auto px-4 py-2 flex items-center justify-between">
        <div className="text-sm">Please verify your email to continue. In dev, open Dev Emails to get the link.</div>
        <div className="flex items-center gap-2">
          <Link data-testid="verify-open-dev-emails" to="/dev/emails" className="text-sm px-3 py-1 bg-yellow-200 rounded">Open Dev Emails</Link>
          <button data-testid="verify-resend" onClick={async()=>{try{await fetch('/api/auth/request-verify',{method:'POST'}); alert('Verification email sent.');}catch(e){alert('Failed to send verification email');}}} className="text-sm px-3 py-1 bg-yellow-200 rounded">Resend verification</button>
        </div>
      </div>
    </div>
  );
}
