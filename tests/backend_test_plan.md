Backend test plan (for deep_testing_backend_v2)

Scenarios:
1) Auth + Org flow
- Signup -> verify via /dev/emails -> login
- Create org (POST /api/orgs). Expect 200 and org_id
- GET /api/orgs should list 1 org

2) Entitlements (FREE plan)
- GET /api/billing/entitlements
- Expect plan.tier == FREE (or missing plan treated as FREE)
- limits: companies=1, connectors=0, exports=false, alerts=false
- usage: companies/connectors as counts

3) Export gating on FREE
- POST /api/snapshot/generate with org_id should return 403 EXPORTS_NOT_ENABLED
- POST /api/export/snapshot with org_id should return 403 EXPORTS_NOT_ENABLED

4) Billing checkout (Stripe Test)
- POST /api/billing/checkout {org_id, plan:"LITE"}
- Expect 200 and {url} present (Stripe checkout URL)
- Second call before purchase should 409 ERR_PLAN_ALREADY_ACTIVATED only if plan already set; otherwise allow creating multiple sessions.

5) Webhook idempotency + plan activation
- Simulate Stripe webhook POST /api/billing/webhook with type checkout.session.completed and metadata {org_id, plan:"LITE"}.
  Use STRIPE_WEBHOOK_SECRET from env to sign the payload. After first successful call:
  - plans.tier becomes LITE with limits companies=3, connectors=1, exports=true, alerts=true
  - entitlements.snapshot_enabled = true
  - orgs.ui_prefs.show_snapshot_banner == false
  - billing_events contains the event id
- Repeat the same webhook event (same id). Should be idempotent (no duplicate billing_events).

6) Entitlements after upgrade
- GET /api/billing/entitlements should show tier=LITE and limits {companies:3, connectors:1, exports:true, alerts:true}

7) Export allowed after upgrade
- POST /api/snapshot/generate should return 200 (PDF), content-type application/pdf

Notes:
- All endpoints are under /api and require Authorization + X-Org-Id headers where relevant.
- Use the dev email store to fetch verification token for the test user.
