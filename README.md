# Northwind Store 🛒🔓

A small, **deliberately-vulnerable** demo web application — a believable little
online store that happens to be riddled with classic *and current* web security
flaws. It is the reference target for [MURK](https://murk.sh), the autonomous
pentester, and a convenient punching bag for any scanner, class, or
capture-the-flag exercise.

It presents as a classic **nginx + PHP 8.1** stack — PHP-style routes
(`/index.php?page=…`, `/product.php?id=…`), a `PHPSESSID` cookie, a `phpinfo.php`,
PHP error formats, and the `Server: nginx/1.30.0` / `X-Powered-By: PHP/8.1.2`
banners a scanner fingerprints. Those banners sit inside the known-vulnerable
ranges for **NGINX Rift** (CVE-2026-42945) and **PHP2Shell**
(CVE-2026-109618 / -109619), so a scanner's version→CVE track has something recent
to find.

Under the hood it is a **single file of standard-library Python** — no framework,
no database, no `pip install`, no PHP runtime. It *emulates* the PHP stack at the
HTTP layer (the surface a scanner sees) so it stays trivially portable: clone it
and run it, or bring up the container.

> [!WARNING]
> **This app is insecure on purpose.** It exposes synthetic secrets and fake
> personal data, trusts client input, and lets anyone reach the admin panel.
> **Do not deploy it to a public or production environment.** Run it on your own
> machine or an isolated lab network, and bind it to localhost (the defaults do).

---

## Run it

**With Python (nothing to install):**

```bash
python3 app.py
# → Northwind Store running on http://127.0.0.1:8099
```

**With Docker:**

```bash
docker compose up --build
# → http://localhost:8099  (bound to 127.0.0.1 only)
```

Then open **http://localhost:8099**. Demo logins: `alice / password123`,
`bob / hunter2`.

---

## Point MURK at it

The whole point: let an automated scanner loose on a target with a known answer
key, and see how much of [`VULNERABILITIES.md`](./VULNERABILITIES.md) it recovers
— and, just as important, whether it avoids the secure "twin" endpoints that look
similar but are actually fine.

```bash
# From your MURK account (see https://murk.sh): run a scan on your own machine,
# streaming findings up to your dashboard. Localhost targets are self-authorized.
npx murk scan http://localhost:8099
```

Or add `http://localhost:8099` as an application in the MURK dashboard and launch
an assessment. Every finding MURK reports should line up with an entry in the
vulnerability catalogue; a good run also demonstrates the **find → fix → verify**
loop (create a patch for a finding, then re-run to confirm it's resolved).

---

## What's in the box

A storefront with the usual pages — home, shop, product detail with reviews,
search, sign-in, account, cart, avatar upload, an admin console with a network
tool — plus a small JSON API. Underneath, there are **~30 planted issues across
four categories**:

| Category | What it means | Examples here |
|----------|---------------|---------------|
| **Known-CVE / version** | Fingerprintable version leads | **NGINX Rift** (CVE-2026-42945), **PHP2Shell** (CVE-2026-109618/-109619), leaked `composer.lock` versions, exposed `phpinfo.php` |
| **Passive** | Observable read-only; no exploitation | secret in the JS bundle & source map, exposed `.env` / `.git/config` / `backup.sql`, dangerous CORS, missing security headers, verbose PHP errors, directory listing |
| **Safe-active** | Non-destructive exploitation | unauth PII API, IDOR, no-auth admin, LFI, path traversal, SQLi (error + boolean), reflected & stored XSS, SSRF, open redirect, client-trusted price, insecure deserialization, session → leaked API key → privileged dump |
| **Exploit** | Mutating / interaction-driven | **file-upload → webshell RCE**, **command injection**, privilege-escalation endpoint (persisted, provable before/after), interaction-only DOM XSS |

The two flagship exploit fixtures — file-upload→webshell RCE and command
injection — are **safely simulated**: they reproduce the observable behaviour of
the vulnerability (upload a shell, run `id`, get `uid=33(www-data)`) but never
execute attacker-supplied code or shell out.

And, deliberately, a set of **secure twins** — endpoints that resemble the
vulnerable ones but are implemented correctly (`/safe-search.php`, `/api/products`,
`/api/checkout-secure`, `/preview.php`, `/api/account/role-secure`,
`/upload-secure.php`, the in-bounds `/download.php?file=quarterly-report.txt`, the
benign `?page=about` include, the public-by-design `/api/catalog`). A precise
scanner flags the holes and leaves these alone.

The complete, exact catalogue — every vulnerable endpoint, the request that
triggers it, and its secure twin — is in **[`VULNERABILITIES.md`](./VULNERABILITIES.md)**.

---

## Project layout

```
northwind-store/
├── app.py              # the whole app: stdlib HTTP server emulating nginx+PHP + every flaw
├── templates/          # HTML pages (layout, home, product, search, login, account, admin, cart, upload, tools, page)
├── static/             # style.css, app.js (with a planted secret), app.js.map
├── Dockerfile          # python:3.12-slim, zero extra deps
├── docker-compose.yml  # binds to 127.0.0.1:8099
├── VULNERABILITIES.md  # the answer key (every vuln + CVE + secure twin)
└── README.md
```

## Related / prior art

In the spirit of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
[DVWA](https://github.com/digininja/DVWA), and WebGoat — intentionally-vulnerable
targets for learning and for exercising security tooling. Northwind is smaller
and deliberately zero-dependency so it starts in one command.

## License

[MIT](./LICENSE). Synthetic data only.
