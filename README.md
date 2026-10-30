# Northwind Store 🛒🔓

A small, **deliberately-vulnerable** demo web application — a believable little
online store that happens to be riddled with classic web security flaws. It is
the reference target for [MURK](https://murk.sh), the autonomous pentester, and a
convenient punching bag for any scanner, class, or capture-the-flag exercise.

It is a **single file of standard-library Python** — no framework, no database to
provision, no `pip install`. Clone it and run it, or bring up the container.

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

A storefront with the usual pages — home, product search, sign-in, account,
cart, and an admin console — plus a small JSON API under `/api`. Underneath,
there are **~20 planted issues across three capability tiers**:

| Tier | What it means | Examples here |
|------|---------------|---------------|
| **Passive** | Observable read-only; no exploitation | secret in the JS bundle & source map, exposed `.env` / `.git/config` / `backup.sql`, GraphQL introspection, dangerous CORS, missing security headers, verbose stack traces, version banner |
| **Safe-active** | Non-destructive exploitation (observe, don't mutate) | unauth PII API, IDOR, no-auth admin console, path traversal, SQL injection (error + boolean oracle), reflected XSS, client-trusted price, SSRF, session → leaked API key → privileged dump |
| **Exploit** | Mutating / interaction-driven | privilege-escalation endpoint (persisted role change, provable before/after), interaction-only DOM XSS in the cart promo field |

And, deliberately, a set of **secure twins** — endpoints that resemble the
vulnerable ones but are implemented correctly (`/safe-search`, `/api/products`,
`/api/checkout-secure`, `/preview`, `/api/account/role-secure`, the in-bounds
`/download?file=quarterly-report.txt`, the public-by-design `/api/catalog`). A
precise scanner flags the holes and leaves these alone.

The complete, exact catalogue — every vulnerable endpoint, the request that
triggers it, and its secure twin — is in **[`VULNERABILITIES.md`](./VULNERABILITIES.md)**.

---

## Project layout

```
northwind-store/
├── app.py              # the whole app: stdlib HTTP server + every planted flaw
├── templates/          # HTML pages (layout, home, search, login, account, admin, cart)
├── static/             # style.css, app.js (with a planted secret), app.js.map
├── Dockerfile          # python:3.12-slim, zero extra deps
├── docker-compose.yml  # binds to 127.0.0.1:8099
├── VULNERABILITIES.md  # the answer key
└── README.md
```

## Related / prior art

In the spirit of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
[DVWA](https://github.com/digininja/DVWA), and WebGoat — intentionally-vulnerable
targets for learning and for exercising security tooling. Northwind is smaller
and deliberately zero-dependency so it starts in one command.

## License

[MIT](./LICENSE). Synthetic data only.
