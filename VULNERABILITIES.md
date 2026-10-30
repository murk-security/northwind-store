# Vulnerability catalogue (the answer key)

Every planted issue in Northwind Store, the exact request that demonstrates it,
and — where one exists — the **secure twin** that does the same thing correctly.
All data and secrets are synthetic.

Assumes the app is on `http://localhost:8099`. Tiers map to how a scanner would
reach the issue: **passive** (read-only observation), **safe-active**
(non-destructive exploitation), **exploit** (mutating / interaction-driven).

---

## Passive — observable without exploitation

| # | Issue | Trigger | Signal |
|---|-------|---------|--------|
| 1 | **Secret in JS bundle** | `GET /static/app.js` | `stripeSecretKey: "sk_live_…"` embedded mid-bundle |
| 2 | **Secret / internal host in source map** | `GET /static/app.js.map` | `sourcesContent` leaks a DB URL + `metrics.internal.northwind.test` |
| 3 | **Exposed `.git/config`** | `GET /.git/config` | reveals `git@github.com:northwind/prod-secrets.git` |
| 4 | **Exposed `.env`** | `GET /.env` | `STRIPE_SECRET_KEY`, `AWS_SECRET_ACCESS_KEY`, DB URL |
| 5 | **Exposed DB backup** | `GET /backup.sql` | `INSERT INTO users …` dump |
| 6 | **GraphQL introspection enabled** | `GET /graphql?query={__schema{types{name}}}` | full type/field schema incl. `passwordHash` |
| 7 | **Dangerous CORS** | `GET /api/data` with `Origin: https://evil.example` | reflects the origin **and** `Access-Control-Allow-Credentials: true` |
| 8 | **Missing security headers** | `GET /` | no `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` |
| 9 | **Verbose error / stack trace** | `GET /api/crash` | leaks a Python traceback and server file paths |
| 10 | **Version fingerprint** | any response | `Server: nginx/1.30.0` banner |

---

## Safe-active — non-destructive exploitation

| # | Issue | Trigger | Signal | Secure twin |
|---|-------|---------|--------|-------------|
| 11 | **Unauthenticated PII API** | `GET /api/users` | returns names, emails, **SSNs** with no auth | `GET /api/catalog` (public-by-design; no PII) |
| 12 | **IDOR** | `GET /api/orders/1002` | reads another customer's order; ids are sequential & unauthenticated | — |
| 13 | **No-auth admin console** | `GET /admin` | full user table (PII) + a delete form, no login required | — |
| 14 | **Path traversal** | `GET /download?file=../private/service.key` | escapes `/srv/public` and returns a private key | in-bounds `GET /download?file=quarterly-report.txt` is fine |
| 15 | **SQL injection — error oracle** | `GET /api/search?q='` | `500` with `unterminated quoted string` DB error | `GET /api/products?q=…` (parametrized) |
| 16 | **SQL injection — boolean oracle** | `GET /api/search?q=zzz'or'1'='1` | tautology surfaces the hidden `Prototype — unreleased` row | `GET /api/products?q=…` |
| 17 | **Reflected XSS** | `GET /search?q=<script>alert(1)</script>` | the query is echoed into HTML unescaped | `GET /safe-search?q=…` (HTML-escaped) |
| 18 | **Client-trusted price** | `GET /api/checkout?item=1&price=0.01` | server charges the client-supplied price | `GET /api/checkout-secure?item=1&price=0.01` (server-authoritative) |
| 19 | **SSRF** | `GET /fetch?url=http://169.254.169.254/` | server makes the request; no allow-list | `GET /preview?url=…` (never fetches server-side) |
| 20 | **Credential / loot chain** | sign in → `GET /account` leaks `api_key` → `GET /api/privileged` with `Authorization: Bearer <api_key>` | any customer key unlocks a full privileged dump of all SSNs | — |

---

## Exploit — mutating / interaction-driven

| # | Issue | Trigger | Proof | Secure twin |
|---|-------|---------|-------|-------------|
| 21 | **Privilege escalation (broken access control / mass assignment)** | `POST /api/account/role` body `{"role":"admin"}` | the change **persists**: `GET /api/account/profile` returns `customer` before and `admin` after | `POST /api/account/role-secure` is refused (`403`); `GET /api/account/profile-secure` never moves |
| 22 | **Interaction-only DOM XSS** | open `/cart`, type a payload into the promo field, click **Apply** | the value is written to `innerHTML`, so injected markup executes — invisible to a plain page fetch | the sink would be safe with `textContent` |

---

## Notes for scanner authors

- The **secure twins** exist to measure precision. Flagging `/safe-search`,
  `/api/products`, `/api/checkout-secure`, `/preview`, `/api/account/role-secure`,
  the in-bounds download, or the public `/api/catalog` as vulnerabilities is a
  **false positive**.
- Issue 20 is a two-hop **chain**: the finding is strongest when a tool recovers
  the key from the authenticated `/account` view and *replays* it against
  `/api/privileged`, rather than reporting the two endpoints in isolation.
- Issue 21 is the cleanest **before/after** demonstration: read the role, mutate
  it, read it again. That persisted state change is what distinguishes a real
  exploit from a probe.
