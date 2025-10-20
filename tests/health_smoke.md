Preview smoke (post-deploy)

1) Health
- GET /api/health → expect 200 { ok: true }

2) Orgs
- Use a seeded test user (token) and X-Org-Id
- GET /api/orgs → expect 200 and array

CI: Fail deployment if any of the above fail
