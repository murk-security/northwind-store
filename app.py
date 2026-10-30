#!/usr/bin/env python3
"""
Northwind Store — a small, deliberately-vulnerable demo web app.

This is an INTENTIONALLY INSECURE application used to demonstrate and test
automated security scanners (it is the reference target for MURK, https://murk.sh).
It is a single-file, zero-dependency Python stdlib server: no pip install, no
database to provision. Clone it and run `python3 app.py`, or `docker compose up`.

It presents as a believable little online store, but every page and API hides one
or more classic web vulnerabilities (secrets in JS, an exposed .env and .git, an
unauthenticated PII API, IDOR, path traversal, SQL injection, reflected and
DOM-based XSS, SSRF, a client-trusted price, a privilege-escalation endpoint, and
more). For most vulnerable endpoint there is a secure "twin" that does the same
thing safely — a good scanner should flag the first and leave the second alone.

The full catalogue (with the exact request that triggers each one) is in
VULNERABILITIES.md. All secrets and personal data here are entirely synthetic.

    !! DO NOT DEPLOY THIS TO A PUBLIC OR PRODUCTION ENVIRONMENT. !!
    It exists to be broken, on your own machine or an isolated lab network.

Run:  python3 app.py [--host 127.0.0.1] [--port 8099]
"""

from __future__ import annotations

import argparse
import html
import json
import os
import posixpath
import re
import secrets
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(HERE, "templates")
STATIC = os.path.join(HERE, "static")

# --- synthetic data ----------------------------------------------------------
# Everything below is fake. The "secret" keys are obviously-demo placeholders.

DEMO_SECRET = "sk_live_PLACEHOLDER_not_a_real_secret"  # synthetic, obviously-fake "Stripe-like" key

USERS = [
    {"id": 1001, "name": "Alice Nguyen",  "email": "alice@northwind.test", "ssn": "001-00-1001", "role": "customer"},
    {"id": 1002, "name": "Bob Okafor",    "email": "bob@northwind.test",   "ssn": "002-00-1002", "role": "customer"},
    {"id": 1003, "name": "Dana Admin",    "email": "dana@northwind.test",  "ssn": "003-00-1003", "role": "admin"},
]
# Orders are keyed by a guessable sequential id — the basis for the IDOR.
ORDERS = {
    "1001": {"order_id": 1001, "owner": "alice@northwind.test", "item": "Cast-iron skillet", "total": 48.00},
    "1002": {"order_id": 1002, "owner": "bob@northwind.test",   "item": "Pour-over kettle",  "total": 62.00},
    "1003": {"order_id": 1003, "owner": "dana@northwind.test",  "item": "Chef's knife",      "total": 120.00},
}
# Public storefront catalogue. "Prototype — unreleased" is NOT reachable by a
# normal search; a SQL tautology that surfaces it proves the injection.
PRODUCTS = [
    {"id": 1, "title": "Cast-iron skillet", "price": 48.00, "sku": "NW-SKL-1"},
    {"id": 2, "title": "Pour-over kettle",  "price": 62.00, "sku": "NW-KTL-2"},
    {"id": 3, "title": "Chef's knife",      "price": 120.00, "sku": "NW-KNF-3"},
    {"id": 4, "title": "Prototype — unreleased", "price": 0.00, "sku": "NW-XXX-0"},
]

GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n"
    '[remote "origin"]\n\turl = git@github.com:northwind/prod-secrets.git\n'
)
DOTENV = (
    f"DATABASE_URL=postgres://admin:{DEMO_SECRET}@db.internal.northwind.test/prod\n"
    f"STRIPE_SECRET_KEY={DEMO_SECRET}\n"
    f"AWS_SECRET_ACCESS_KEY={DEMO_SECRET}\n"
)
BACKUP_SQL = (
    "-- nightly dump (synthetic)\n"
    "INSERT INTO users VALUES (1003,'dana@northwind.test','admin','003-00-1003');\n"
)
GRAPHQL_SCHEMA = {"data": {"__schema": {"types": [
    {"name": "User", "fields": ["id", "email", "ssn", "passwordHash"]},
    {"name": "Query", "fields": ["users", "order"]},
]}}}

# Virtual filesystem for the /download path-traversal endpoint. It is meant to
# serve only /srv/public/*, but it resolves user input without confining to that
# base, so "../private/service.key" escapes.
VFS = {
    "/srv/public/quarterly-report.txt": "Northwind public quarterly report — synthetic, safe to share.\n",
    "/srv/private/service.key": f"-----BEGIN PRIVATE KEY-----\n{DEMO_SECRET}\n-----END PRIVATE KEY-----\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nnorthwind:x:1000:1000::/home/northwind:/bin/sh\n",
}

# Login / session state. Synthetic creds.
CREDS = {"alice": "password123", "bob": "hunter2"}
SESSIONS: dict[str, str] = {}
SESS_LOCK = threading.Lock()

# Per-user API keys — recoverable from the authenticated /account view, and a
# valid key (even a plain customer's) unlocks /api/privileged. This is a two-hop
# kill chain: session -> recovered key -> privileged dump.
API_KEYS = {"alice": "ak_live_alice_DEMO00000000", "bob": "ak_live_bob_DEMO00000000"}

# Mutable role state for the privilege-escalation endpoint. "v" is the vulnerable
# resource (its role can be changed by anyone); "s" is the secure twin (refused).
# A follow-up GET reads these back, so a real, persistent change is provable.
ROLE_STATE = {"v": "customer", "s": "customer"}
ROLE_LOCK = threading.Lock()


def _load_templates() -> dict[str, str]:
    out: dict[str, str] = {}
    for fn in os.listdir(TEMPLATES):
        if fn.endswith(".html"):
            with open(os.path.join(TEMPLATES, fn), encoding="utf-8") as fh:
                out[fn[:-5]] = fh.read()
    return out


TPL = _load_templates()


def render(page: str, **ctx) -> bytes:
    """Minimal {{token}} templating: drop a page fragment into the layout."""
    body = TPL.get(page, "")
    for k, v in ctx.items():
        body = body.replace("{{" + k + "}}", str(v))
    shell = TPL["layout"].replace("{{content}}", body)
    shell = shell.replace("{{title}}", ctx.get("title", "Northwind Store"))
    # strip any tokens the page did not fill
    shell = re.sub(r"\{\{[a-z_]+\}\}", "", shell)
    return shell.encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # A version fingerprint leaked in the Server banner.
    server_version = "nginx/1.30.0"
    sys_version = ""

    def log_message(self, fmt, *a):  # keep the console quiet
        pass

    # --- response helpers ---
    def _send(self, code: int, body: bytes, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # NOTE: no Content-Security-Policy / Strict-Transport-Security / X-Frame-Options.
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, indent=2).encode(), "application/json", extra)

    def _session_user(self):
        cookie = self.headers.get("Cookie", "")
        mm = re.search(r"session=([A-Za-z0-9]+)", cookie)
        with SESS_LOCK:
            return SESSIONS.get(mm.group(1)) if mm else None

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self._send(200, b"", "text/plain", extra={"Allow": "GET, HEAD, POST, OPTIONS"})

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""

        if path == "/login":
            form = parse_qs(raw.decode("utf-8", "replace"))
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]
            if user in CREDS and CREDS[user] == pw:
                token = secrets.token_hex(8)
                with SESS_LOCK:
                    SESSIONS[token] = user
                # Redirect to the account page with the new session cookie.
                return self._send(303, b"", "text/html",
                                  extra={"Set-Cookie": f"session={token}; HttpOnly; Path=/",
                                         "Location": "/account"})
            return self._send(200, render("login", title="Sign in",
                                          error="Invalid username or password."))

        if path == "/api/account/role":
            # Broken access control / mass assignment: anyone may set their own
            # role, with no check that the caller is already privileged. The change
            # PERSISTS, so GET /api/account/profile proves the escalation stuck.
            try:
                body = json.loads(raw.decode("utf-8", "replace") or "{}")
            except json.JSONDecodeError:
                return self._json(400, {"error": "bad json"})
            role = str(body.get("role", "")) or "customer"
            with ROLE_LOCK:
                ROLE_STATE["v"] = role
            return self._json(200, {"ok": True, "role": role})

        if path == "/api/account/role-secure":
            # Same action, properly guarded: only an admin may set roles, and no
            # caller here is an admin, so it is always refused. State never moves.
            return self._json(403, {"ok": False, "error": "forbidden: admin privilege required"})

        return self._json(501, {"error": "not implemented"})

    # ------------------------------------------------------------------- GET
    def do_GET(self):
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)

        # --- static files (served generically from ./static) ---
        if path.startswith("/static/"):
            rel = posixpath.normpath(path[len("/static/"):])
            fp = os.path.join(STATIC, rel)
            if os.path.isfile(fp) and fp.startswith(STATIC):
                ctype = ("application/javascript" if fp.endswith(".js")
                         else "application/json" if fp.endswith(".map")
                         else "text/css" if fp.endswith(".css")
                         else "application/octet-stream")
                with open(fp, "rb") as fh:
                    return self._send(200, fh.read(), ctype)
            return self._json(404, {"error": "not found"})

        # --- exposed sensitive files (misconfigured web root) ---
        if path == "/.git/config":
            return self._send(200, GIT_CONFIG.encode(), "text/plain")
        if path == "/.env":
            return self._send(200, DOTENV.encode(), "text/plain")
        if path == "/backup.sql":
            return self._send(200, BACKUP_SQL.encode(), "text/plain")

        # --- pages ---
        if path == "/":
            cards = "".join(
                f'<article class="card"><div class="thumb">{html.escape(p["title"][:1])}</div>'
                f'<h3>{html.escape(p["title"])}</h3>'
                f'<p class="price">${p["price"]:.2f}</p>'
                f'<a class="btn" href="/search?q={html.escape(p["title"].split()[0])}">View</a></article>'
                for p in PRODUCTS if p["id"] != 4
            )
            return self._send(200, render("home", title="Northwind Store", cards=cards))

        if path == "/search":
            # Reflected XSS: the query is echoed into HTML without escaping.
            term = q.get("q", [""])[0]
            rows = [p for p in PRODUCTS if term.lower() in p["title"].lower()]
            results = "".join(
                f'<li>{html.escape(r["title"])} — ${r["price"]:.2f}</li>' for r in rows
            ) or "<li class='muted'>No products matched.</li>"
            # BUG: `term` is interpolated raw into the heading.
            heading = f"Results for “{term}”"
            return self._send(200, render("search", title="Search", heading=heading, results=results))

        if path == "/safe-search":
            # Secure twin: the reflected term is HTML-escaped.
            term = q.get("q", [""])[0]
            rows = [p for p in PRODUCTS if term.lower() in p["title"].lower()]
            results = "".join(
                f'<li>{html.escape(r["title"])} — ${r["price"]:.2f}</li>' for r in rows
            ) or "<li class='muted'>No products matched.</li>"
            heading = f"Results for “{html.escape(term)}”"
            return self._send(200, render("search", title="Search", heading=heading, results=results))

        if path == "/login":
            return self._send(200, render("login", title="Sign in", error=""))

        if path == "/account":
            user = self._session_user()
            if not user:
                return self._send(200, render("login", title="Sign in",
                                              error="Please sign in to view your account."))
            rec = next((x for x in USERS if x["email"].split("@")[0] == user), USERS[0])
            # The account view leaks the user's API key — recoverable loot.
            return self._send(200, render("account", title="My account",
                                          name=html.escape(rec["name"]),
                                          email=html.escape(rec["email"]),
                                          ssn=html.escape(rec["ssn"]),
                                          api_key=API_KEYS.get(user, "—")))

        if path == "/admin":
            # Auth-boundary failure: the admin console requires no authentication
            # and exposes real customer PII plus a destructive delete form.
            rows = "".join(
                f"<tr><td>{u['id']}</td><td>{html.escape(u['name'])}</td>"
                f"<td>{html.escape(u['email'])}</td><td>{u['ssn']}</td><td>{u['role']}</td></tr>"
                for u in USERS
            )
            return self._send(200, render("admin", title="Admin", rows=rows))

        if path == "/cart":  # a static client-rendered page that reads an interaction sink
            # Interaction-only DOM XSS: the "promo code" field is written to innerHTML
            # on click. A plain page load shows nothing; it takes a fill + click.
            return self._send(200, render("cart", title="Cart"))

        # --- JSON APIs ---
        if path == "/api/catalog":
            # Public-by-design storefront data. NOT a vulnerability: a scanner
            # should resist flagging this "unauthenticated API returns data".
            return self._json(200, [{"id": p["id"], "title": p["title"],
                                     "price": p["price"], "sku": p["sku"]} for p in PRODUCTS if p["id"] != 4])

        if path == "/api/users":
            # Unauthenticated PII API (genuine).
            return self._json(200, USERS)

        if path == "/api/account/profile":
            with ROLE_LOCK:
                return self._json(200, {"role": ROLE_STATE["v"]})
        if path == "/api/account/profile-secure":
            with ROLE_LOCK:
                return self._json(200, {"role": ROLE_STATE["s"]})

        if path == "/api/privileged":
            # Any valid customer api_key unlocks a full privileged dump (all SSNs).
            auth = self.headers.get("Authorization", "")
            bm = re.match(r"(?i)bearer\s+(\S+)", auth)
            token = bm.group(1) if bm else None
            if token and token in set(API_KEYS.values()):
                return self._json(200, {"privileged": True, "users": USERS})
            return self._json(401, {"error": "bearer token required"})

        m = re.match(r"^/api/orders/(\d+)$", path)
        if m:
            # IDOR: any order id, no ownership check, no auth.
            o = ORDERS.get(m.group(1))
            return self._json(200 if o else 404, o or {"error": "not found"})

        if path == "/api/search":
            # Simulated SQL injection over a string-built query
            # (SELECT id,title FROM products WHERE title LIKE '%<q>%'). An unbalanced
            # quote raises a DB error (error oracle); a tautology surfaces the hidden
            # "Prototype — unreleased" row (boolean oracle).
            term = q.get("q", [""])[0]
            if term.count("'") % 2 == 1:
                return self._send(500, (
                    "psycopg2.errors.SyntaxError: unterminated quoted string at or near "
                    f"\"'{term}\"\nLINE 1: ...title LIKE '%{term}%'\n").encode(), "text/plain")
            norm = term.lower().replace(" ", "")
            if "or'1'='1" in norm or "or1=1" in norm:
                rows = PRODUCTS
            elif "and'1'='2" in norm or "and1=2" in norm:
                rows = []
            else:
                rows = [p for p in PRODUCTS if term.lower() in p["title"].lower()]
            return self._json(200, rows)

        if path == "/api/products":
            # Parametrized query: NOT injectable (secure twin of /api/search).
            term = q.get("q", [""])[0]
            return self._json(200, [p for p in PRODUCTS if term.lower() in p["title"].lower()])

        if path == "/api/checkout":
            # Business-logic flaw: the server trusts a client-supplied price.
            item = q.get("item", ["1"])[0]
            try:
                price = float(q.get("price", ["0"])[0] or 0)
            except ValueError:
                price = 0.0
            return self._json(200, {"item": item, "charged": price, "list_price": 48.00, "status": "ok"})
        if path == "/api/checkout-secure":
            # Server-authoritative price (secure twin): tampering is ignored.
            item = q.get("item", ["1"])[0]
            return self._json(200, {"item": item, "charged": 48.00, "list_price": 48.00, "status": "ok"})

        if path == "/download":
            # Path traversal: user input is resolved against /srv/public without
            # confining the result, so "../private/service.key" escapes.
            name = q.get("file", [""])[0]
            resolved = posixpath.normpath("/srv/public/" + name)
            if resolved in VFS:
                return self._send(200, VFS[resolved].encode(), "text/plain")
            return self._json(404, {"error": "no such file", "resolved": resolved})

        if path == "/fetch":
            # SSRF: fetches a user-supplied URL server-side with no allow-list.
            url = q.get("url", [""])[0]
            ok = False
            if url.startswith(("http://", "https://")):
                try:
                    with urllib.request.urlopen(url, timeout=3) as r:
                        r.read(1000)
                        ok = True
                except Exception:
                    ok = False
            return self._json(200, {"fetched": ok, "url": url})
        if path == "/preview":
            # Secure twin: accepts a url but never fetches it server-side.
            return self._json(200, {"preview_of": q.get("url", [""])[0],
                                    "note": "rendered client-side; not fetched server-side"})

        if path == "/graphql":
            # Introspection enabled over GET.
            if "query" in q and "__schema" in q["query"][0]:
                return self._json(200, GRAPHQL_SCHEMA)
            return self._json(200, {"data": None})

        if path == "/api/data":
            # Dangerous CORS: reflects an arbitrary origin AND allows credentials.
            origin = self.headers.get("Origin", "https://evil.example")
            return self._json(200, {"data": [1, 2, 3]}, extra={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true"})

        if path == "/api/crash":
            # Verbose error: leaks a stack trace and server internals.
            tb = ('Traceback (most recent call last):\n'
                  '  File "/srv/northwind/app/api.py", line 88, in handler\n'
                  '    row = db.execute("SELECT * FROM users WHERE id=%s" % uid)\n'
                  'psycopg2.ProgrammingError: syntax error at or near "%"\n')
            return self._send(500, tb.encode(), "text/plain")

        return self._json(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser(description="Northwind Store — deliberately-vulnerable demo app.")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8099")))
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"Northwind Store running on http://{a.host}:{a.port}  (intentionally vulnerable — do not expose)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
