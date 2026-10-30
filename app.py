#!/usr/bin/env python3
"""
Northwind Store — a small, deliberately-vulnerable demo web application.

This is an INTENTIONALLY INSECURE app used to demonstrate and test automated
security scanners (it is the reference target for MURK, https://murk.sh).

It presents as a believable little online store running on a classic
**nginx + PHP 8.1** stack: PHP-style routes (`/index.php?page=…`, `/product.php?id=…`),
a `PHPSESSID` session cookie, a `phpinfo.php`, PHP error formats, and the
`Server: nginx/1.30.0` / `X-Powered-By: PHP/8.1.2` banners a scanner fingerprints.
Those two banners fall inside the known-vulnerable ranges for **NGINX Rift**
(CVE-2026-42945) and **PHP2Shell** (CVE-2026-109618 / -109619) — so a scanner's
version→CVE track should surface them as leads.

For portability the whole thing is a SINGLE FILE of standard-library Python — no
framework, no database, no `pip install`, no PHP runtime. It *emulates* the PHP
stack at the HTTP layer (which is the surface a scanner sees). The two flagship
exploit fixtures — file-upload→webshell RCE and command injection — are
**simulated**: they reproduce the observable behaviour of the vulnerability but
never execute attacker-supplied code or shell out. Everything else behaves for
real against the HTTP surface.

The full catalogue (every vulnerable request + its secure twin, mapped to CVEs and
action tiers) is in VULNERABILITIES.md. All secrets and personal data are synthetic
and obviously fake.

    !! DO NOT DEPLOY THIS TO A PUBLIC OR PRODUCTION ENVIRONMENT. !!
    It exists to be broken, on your own machine or an isolated lab network.

Run:  python3 app.py [--host 127.0.0.1] [--port 8099]
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import posixpath
import re
import secrets
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(HERE, "templates")
STATIC = os.path.join(HERE, "static")

# Banners a scanner fingerprints -> version->CVE leads (see VULNERABILITIES.md).
SERVER_BANNER = "nginx/1.30.0"          # CVE-2026-42945 "NGINX Rift" (<= 1.30.0)
PHP_VERSION = "8.1.2"                    # CVE-2026-109618/-109619 "PHP2Shell" (< 8.2.35; EOL branch)

# --- synthetic data ----------------------------------------------------------
# Everything below is fake. The "secret" keys are obviously-demo placeholders.

DEMO_SECRET = "sk_live_PLACEHOLDER_not_a_real_secret"

USERS = [
    {"id": 1001, "name": "Alice Nguyen", "email": "alice@northwind.test", "ssn": "001-00-1001", "role": "customer"},
    {"id": 1002, "name": "Bob Okafor",   "email": "bob@northwind.test",   "ssn": "002-00-1002", "role": "customer"},
    {"id": 1003, "name": "Dana Reyes",   "email": "dana@northwind.test",  "ssn": "003-00-1003", "role": "admin"},
]
ORDERS = {
    "1001": {"order_id": 1001, "owner": "alice@northwind.test", "item": "Cast-iron skillet", "total": 48.00},
    "1002": {"order_id": 1002, "owner": "bob@northwind.test",   "item": "Pour-over kettle",  "total": 62.00},
    "1003": {"order_id": 1003, "owner": "dana@northwind.test",  "item": "Chef's knife",      "total": 120.00},
}
PRODUCTS = [
    {"id": 1, "title": "Cast-iron skillet", "price": 48.00,  "sku": "NW-SKL-1", "blurb": "Pre-seasoned, lasts a lifetime."},
    {"id": 2, "title": "Pour-over kettle",  "price": 62.00,  "sku": "NW-KTL-2", "blurb": "Gooseneck spout, precise pour."},
    {"id": 3, "title": "Chef's knife",      "price": 120.00, "sku": "NW-KNF-3", "blurb": "High-carbon steel, hand-finished."},
    {"id": 4, "title": "Prototype — unreleased", "price": 0.00, "sku": "NW-XXX-0", "blurb": "Internal only."},
]
# Product reviews — stored, and rendered WITHOUT escaping (stored XSS).
REVIEWS: dict[str, list[str]] = {"1": ["Fantastic skillet, use it daily."], "2": [], "3": []}
REVIEWS_LOCK = threading.Lock()

GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n"
    '[remote "origin"]\n\turl = git@github.com:northwind/prod-secrets.git\n'
)
DOTENV = (
    f"APP_ENV=production\nDATABASE_URL=mysql://admin:{DEMO_SECRET}@db.internal.northwind.test/prod\n"
    f"STRIPE_SECRET_KEY={DEMO_SECRET}\nAWS_SECRET_ACCESS_KEY={DEMO_SECRET}\n"
)
BACKUP_SQL = (
    "-- nightly dump (synthetic)\n"
    "INSERT INTO users VALUES (1003,'dana@northwind.test','admin','003-00-1003');\n"
)
# A composer.lock leaks the exact dependency versions (feeds a version->CVE sweep).
COMPOSER_LOCK = json.dumps({
    "packages": [
        {"name": "monolog/monolog", "version": "2.9.1"},
        {"name": "guzzlehttp/guzzle", "version": "7.4.5"},
        {"name": "twig/twig", "version": "3.4.1"},
    ]
}, indent=2)

# Virtual filesystem for the /download.php traversal and /index.php?page= LFI.
VFS = {
    "/var/www/html/pages/about": "<h1>About Northwind</h1><p>Family-run kitchenware since 1998.</p>",
    "/var/www/html/pages/shipping": "<h1>Shipping</h1><p>Free over $50. 2–4 business days.</p>",
    "/srv/public/quarterly-report.txt": "Northwind public quarterly report — synthetic, safe to share.\n",
    "/srv/private/service.key": f"-----BEGIN PRIVATE KEY-----\n{DEMO_SECRET}\n-----END PRIVATE KEY-----\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nnorthwind:x:1000:1000::/home/northwind:/bin/sh\n",
}

CREDS = {"alice": "password123", "bob": "hunter2"}
SESSIONS: dict[str, str] = {}
SESS_LOCK = threading.Lock()
API_KEYS = {"alice": "ak_live_alice_DEMO00000000", "bob": "ak_live_bob_DEMO00000000"}

ROLE_STATE = {"v": "customer", "s": "customer"}
ROLE_LOCK = threading.Lock()

# Uploaded files live here (in memory). The vulnerable /upload.php accepts any
# extension; /uploads/<name> then serves (and "executes") them.
UPLOADS: dict[str, bytes] = {}
UPLOADS_LOCK = threading.Lock()

# Simulated command output for the webshell / command-injection fixtures. These
# return canned, realistic output for a small allow-list of read-only commands and
# NEVER execute anything. Anything else returns a generic marker.
_FAKE_CMD = {
    "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "whoami": "www-data",
    "uname -a": "Linux northwind-web 6.1.0-northwind #1 SMP x86_64 GNU/Linux",
    "pwd": "/var/www/html",
    "ls": "index.php\nconfig.php\nuploads\nvendor",
    "hostname": "northwind-web",
    "cat /etc/passwd": VFS["/etc/passwd"].strip(),
}


def _sim_command(cmd: str) -> str:
    """Return canned output for a read-only command; never executes anything."""
    cmd = cmd.strip()
    return _FAKE_CMD.get(cmd, f"sh: executed: {cmd}")


# --- minimal PHP-ish serialization (for the insecure-deserialization fixture) ---

def php_serialize_identity(user: str, role: str) -> str:
    return (f'a:2:{{s:4:"user";s:{len(user)}:"{user}";'
            f's:4:"role";s:{len(role)}:"{role}";}}')


def php_parse_role(blob: str) -> tuple[str | None, str | None]:
    """Pull user/role out of a PHP-serialized array string. This stands in for a
    trusting `unserialize($_COOKIE['remember'])` — the values are trusted as-is, so
    a tampered cookie forges identity. (No real object injection; string parse only.)"""
    um = re.search(r's:4:"user";s:\d+:"([^"]*)"', blob)
    rm = re.search(r's:4:"role";s:\d+:"([^"]*)"', blob)
    return (um.group(1) if um else None, rm.group(1) if rm else None)


# --- templating --------------------------------------------------------------

def _load_templates() -> dict[str, str]:
    out: dict[str, str] = {}
    for fn in os.listdir(TEMPLATES):
        if fn.endswith(".html"):
            with open(os.path.join(TEMPLATES, fn), encoding="utf-8") as fh:
                out[fn[:-5]] = fh.read()
    return out


TPL = _load_templates()


def render(page: str, **ctx) -> bytes:
    body = TPL.get(page, "")
    for k, v in ctx.items():
        body = body.replace("{{" + k + "}}", str(v))
    shell = TPL["layout"].replace("{{content}}", body)
    shell = shell.replace("{{title}}", ctx.get("title", "Northwind Store"))
    shell = re.sub(r"\{\{[a-z_]+\}\}", "", shell)
    return shell.encode()


def _parse_multipart(raw: bytes, content_type: str) -> dict:
    """Tiny multipart/form-data parser: returns {name: value} for text fields and
    {name: (filename, bytes)} for file fields. Good enough for the upload fixture."""
    m = re.search(r"boundary=(.+)$", content_type)
    if not m:
        return {}
    boundary = ("--" + m.group(1).strip().strip('"')).encode()
    out: dict = {}
    for part in raw.split(boundary):
        if not part.strip() or part.strip() == b"--":
            continue
        head, _, data = part.partition(b"\r\n\r\n")
        if not _:
            continue
        data = data.rstrip(b"\r\n")
        htxt = head.decode("utf-8", "replace")
        nm = re.search(r'name="([^"]*)"', htxt)
        fn = re.search(r'filename="([^"]*)"', htxt)
        if not nm:
            continue
        if fn:
            out[nm.group(1)] = (fn.group(1), data)
        else:
            out[nm.group(1)] = data.decode("utf-8", "replace")
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = SERVER_BANNER
    sys_version = ""

    def log_message(self, fmt, *a):
        pass

    # --- response helpers (all responses carry the PHP stack banners) ---
    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", f"PHP/{PHP_VERSION}")
        # NOTE: no Content-Security-Policy / Strict-Transport-Security / X-Frame-Options.
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, indent=2).encode(), "application/json", extra)

    def _php_fatal(self, msg, file="/var/www/html/includes/db.php", line=88):
        # Verbose PHP error: leaks absolute paths + a stack trace.
        body = (f"<b>Fatal error</b>: Uncaught {msg} in <b>{file}</b> on line <b>{line}</b>\n"
                f"Stack trace:\n#0 {file}({line}): PDO->query()\n"
                f"#1 /var/www/html/product.php(42): Database->find()\n#2 {{main}}\n")
        return self._send(500, body.encode(), "text/html")

    def _cookies(self) -> dict:
        out = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def _identity(self):
        """Resolve the caller: a real PHPSESSID session, else a TRUSTED 'remember'
        cookie (insecure deserialization). Returns (user, role)."""
        ck = self._cookies()
        token = ck.get("PHPSESSID")
        if token:
            with SESS_LOCK:
                user = SESSIONS.get(token)
            if user:
                rec = next((u for u in USERS if u["email"].split("@")[0] == user), None)
                return user, (rec["role"] if rec else "customer")
        remember = ck.get("remember")
        if remember:
            try:
                blob = base64.b64decode(remember + "===").decode("utf-8", "replace")
            except Exception:
                return None, None
            return php_parse_role(blob)  # trusted as-is -> tamperable
        return None, None

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self._send(200, b"", "text/plain", extra={"Allow": "GET, HEAD, POST, OPTIONS"})

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")

        if path in ("/login.php", "/login"):
            form = parse_qs(raw.decode("utf-8", "replace"))
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]
            remember = form.get("remember", [""])[0]
            if user in CREDS and CREDS[user] == pw:
                token = secrets.token_hex(8)
                with SESS_LOCK:
                    SESSIONS[token] = user
                rec = next((u for u in USERS if u["email"].split("@")[0] == user), None)
                role = rec["role"] if rec else "customer"
                extra = {"Set-Cookie": f"PHPSESSID={token}; Path=/; HttpOnly",
                         "Location": "/account.php"}
                if remember:
                    # "Remember me" stores a serialized identity cookie, trusted on return.
                    blob = base64.b64encode(php_serialize_identity(user, role).encode()).decode()
                    extra["Set-Cookie"] = extra["Set-Cookie"] + f", remember={blob}; Path=/"
                return self._send(303, b"", "text/html", extra=extra)
            return self._send(200, render("login", title="Sign in",
                                          error="Invalid username or password."))

        if path in ("/product.php",):
            # Stored XSS: a review body is stored and later rendered unescaped.
            q = parse_qs(urlparse(self.path).query)
            pid = q.get("id", ["1"])[0]
            form = parse_qs(raw.decode("utf-8", "replace"))
            review = form.get("review", [""])[0]
            if review:
                with REVIEWS_LOCK:
                    REVIEWS.setdefault(pid, []).append(review)
            return self._send(303, b"", "text/html", extra={"Location": f"/product.php?id={pid}"})

        if path in ("/upload.php",):
            # Unrestricted file upload: no extension/content check, stored under the
            # web root at /uploads/<name> where it is then served and "executed".
            fields = _parse_multipart(raw, ctype)
            f = fields.get("avatar")
            if not isinstance(f, tuple):
                return self._send(200, render("upload", title="Upload avatar",
                                              msg="Choose a file to upload.", link=""))
            name, data = f
            name = posixpath.basename(name) or "file"
            with UPLOADS_LOCK:
                UPLOADS[name] = data
            url = f"/uploads/{quote(name)}"
            return self._send(200, render("upload", title="Upload avatar",
                                          msg=f"Uploaded {html.escape(name)} ({len(data)} bytes).",
                                          link=f'<a href="{url}">{html.escape(url)}</a>'))

        if path in ("/upload-secure.php",):
            # Secure twin: allow-lists image extensions and rejects everything else.
            fields = _parse_multipart(raw, ctype)
            f = fields.get("avatar")
            if isinstance(f, tuple) and f[0].lower().rsplit(".", 1)[-1] in ("png", "jpg", "jpeg", "gif", "webp"):
                return self._send(200, render("upload", title="Upload avatar",
                                              msg="Image accepted.", link=""))
            return self._send(415, render("upload", title="Upload avatar",
                                          msg="Rejected: only image files are allowed.", link=""))

        if path == "/api/account/role":
            # Broken access control / mass assignment: anyone sets their own role; it
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
            return self._json(403, {"ok": False, "error": "forbidden: admin privilege required"})

        return self._json(501, {"error": "not implemented"})

    # ------------------------------------------------------------------- GET
    def do_GET(self):
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)

        # --- static assets ---
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

        # --- uploaded files: served AND "executed" from the web root ---
        if path.startswith("/uploads/"):
            name = posixpath.basename(path)
            if name in ("", None):
                # Directory listing enabled on /uploads/.
                with UPLOADS_LOCK:
                    items = "".join(f'<li><a href="/uploads/{quote(n)}">{html.escape(n)}</a></li>'
                                    for n in UPLOADS) or "<li>(empty)</li>"
                return self._send(200, (f"<html><head><title>Index of /uploads/</title></head>"
                                        f"<body><h1>Index of /uploads/</h1><ul>{items}</ul></body></html>").encode())
            with UPLOADS_LOCK:
                data = UPLOADS.get(name)
            if data is None:
                return self._json(404, {"error": "not found"})
            if name.lower().endswith((".php", ".phtml", ".php5")):
                # The server treats uploaded PHP as executable. If it looks like a
                # webshell, SIMULATE running the ?cmd= / ?c= argument (never real exec).
                src = data.decode("utf-8", "replace")
                if re.search(r"system\s*\(|shell_exec\s*\(|passthru\s*\(|\beval\s*\(|exec\s*\(", src):
                    cmd = q.get("cmd", q.get("c", [""]))[0]
                    out = _sim_command(cmd) if cmd else "(webshell ready — pass ?cmd=)"
                    return self._send(200, out.encode(), "text/plain")
                return self._send(200, b"", "text/html")  # executed, no output
            # non-executable upload: served as-is
            return self._send(200, data, "application/octet-stream")

        # --- exposed sensitive files (misconfigured web root) ---
        if path == "/.git/config":
            return self._send(200, GIT_CONFIG.encode(), "text/plain")
        if path == "/.env":
            return self._send(200, DOTENV.encode(), "text/plain")
        if path == "/backup.sql":
            return self._send(200, BACKUP_SQL.encode(), "text/plain")
        if path == "/composer.lock":
            return self._send(200, COMPOSER_LOCK.encode(), "application/json")
        if path == "/phpinfo.php":
            return self._send(200, self._phpinfo().encode())

        # --- pages ---
        if path in ("/", "/index.php"):
            page = q.get("page", [""])[0]
            if page and page not in ("home", ""):
                # LFI: the front controller includes a user-named file with no
                # confinement, so ../ (or an absolute path) escapes the pages dir.
                resolved = posixpath.normpath("/var/www/html/pages/" + page)
                if resolved in VFS:
                    return self._send(200, render("page", title=page.title(), body=VFS[resolved]))
                if page in VFS:  # absolute path include
                    return self._send(200, self._send_text_page(page, VFS[page]))
                if posixpath.normpath(page) in VFS:
                    return self._send(200, self._send_text_page(page, VFS[posixpath.normpath(page)]))
                return self._send(200, render("page", title="Not found",
                                              body=f"<pre>Warning: include({html.escape(page)}): "
                                                   f"failed to open stream: No such file or directory</pre>"))
            cards = "".join(
                f'<article class="card"><div class="thumb">{html.escape(p["title"][:1])}</div>'
                f'<h3>{html.escape(p["title"])}</h3><p class="price">${p["price"]:.2f}</p>'
                f'<a class="btn" href="/product.php?id={p["id"]}">View</a></article>'
                for p in PRODUCTS if p["id"] != 4
            )
            return self._send(200, render("home", title="Northwind Store", cards=cards))

        if path in ("/shop.php",):
            cards = "".join(
                f'<article class="card"><div class="thumb">{html.escape(p["title"][:1])}</div>'
                f'<h3>{html.escape(p["title"])}</h3><p class="price">${p["price"]:.2f}</p>'
                f'<p class="muted">{html.escape(p["blurb"])}</p>'
                f'<a class="btn" href="/product.php?id={p["id"]}">View</a></article>'
                for p in PRODUCTS if p["id"] != 4
            )
            return self._send(200, render("home", title="Shop", cards=cards))

        if path in ("/product.php",):
            pid = q.get("id", ["1"])[0]
            p = next((x for x in PRODUCTS if str(x["id"]) == pid), None)
            if not p:
                return self._php_fatal('PDOException: SQLSTATE[HY000]: product not found', line=42)
            with REVIEWS_LOCK:
                revs = list(REVIEWS.get(pid, []))
            # Stored XSS: review bodies are interpolated raw.
            review_html = "".join(f"<li>{r}</li>" for r in revs) or "<li class='muted'>No reviews yet.</li>"
            return self._send(200, render("product", title=p["title"],
                                          name=html.escape(p["title"]), price=f'{p["price"]:.2f}',
                                          sku=html.escape(p["sku"]), blurb=html.escape(p["blurb"]),
                                          pid=pid, reviews=review_html))

        if path in ("/search.php", "/search"):
            term = q.get("q", [""])[0]
            rows = [p for p in PRODUCTS if term.lower() in p["title"].lower()]
            results = "".join(f'<li><a href="/product.php?id={r["id"]}">{html.escape(r["title"])}</a>'
                              f' — ${r["price"]:.2f}</li>' for r in rows) or "<li class='muted'>No products matched.</li>"
            heading = f"Results for “{term}”"  # reflected XSS: raw
            return self._send(200, render("search", title="Search", heading=heading, results=results))
        if path in ("/safe-search.php", "/safe-search"):
            term = q.get("q", [""])[0]
            rows = [p for p in PRODUCTS if term.lower() in p["title"].lower()]
            results = "".join(f'<li>{html.escape(r["title"])} — ${r["price"]:.2f}</li>' for r in rows) \
                or "<li class='muted'>No products matched.</li>"
            return self._send(200, render("search", title="Search",
                                          heading=f"Results for “{html.escape(term)}”", results=results))

        if path in ("/login.php", "/login"):
            return self._send(200, render("login", title="Sign in", error=""))

        if path in ("/account.php", "/account"):
            user, role = self._identity()
            if not user:
                return self._send(200, render("login", title="Sign in",
                                              error="Please sign in to view your account."))
            rec = next((x for x in USERS if x["email"].split("@")[0] == user), USERS[0])
            admin_link = ('<p><a class="btn" href="/admin/">Open admin dashboard</a></p>'
                          if role == "admin" else "")
            return self._send(200, render("account", title="My account",
                                          name=html.escape(rec["name"]), email=html.escape(rec["email"]),
                                          ssn=html.escape(rec["ssn"]), role=html.escape(role or ""),
                                          api_key=API_KEYS.get(user, "—"), admin_link=admin_link))

        if path in ("/admin/", "/admin", "/admin/index.php"):
            # Auth-boundary failure: admin requires no authentication.
            rows = "".join(
                f"<tr><td>{u['id']}</td><td>{html.escape(u['name'])}</td>"
                f"<td>{html.escape(u['email'])}</td><td>{u['ssn']}</td><td>{u['role']}</td></tr>"
                for u in USERS)
            return self._send(200, render("admin", title="Admin", rows=rows))

        if path in ("/tools.php",):
            # Command injection: host is passed to a shell `ping` with no sanitising.
            host = q.get("host", [""])[0]
            output = ""
            if host:
                if re.search(r"[;&|`]|\$\(", host):
                    # injected command after a metacharacter -> SIMULATE it (never exec)
                    inj = re.split(r"[;&|]|\$\(|`", host, maxsplit=1)[-1].strip().rstrip(")`")
                    output = f"PING {host.split(';')[0].strip()}: 1 packets transmitted\n{_sim_command(inj)}"
                else:
                    output = f"PING {host}: 56 data bytes\n64 bytes from {host}: icmp_seq=0 ttl=64 time=0.1 ms"
            return self._send(200, render("tools", title="Network tools",
                                          host=html.escape(host), output=html.escape(output)))

        if path in ("/cart.php", "/cart"):
            return self._send(200, render("cart", title="Cart"))

        if path in ("/upload.php",):
            return self._send(200, render("upload", title="Upload avatar",
                                          msg="Upload a profile picture.", link=""))

        if path in ("/redirect.php",):
            # Open redirect: no allow-list on the destination.
            target = q.get("url", ["/"])[0]
            return self._send(302, b"", "text/html", extra={"Location": target})

        if path in ("/fetch.php", "/fetch"):
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
        if path in ("/preview.php", "/preview"):
            return self._json(200, {"preview_of": q.get("url", [""])[0],
                                    "note": "rendered client-side; not fetched server-side"})

        if path in ("/download.php", "/download"):
            name = q.get("file", [""])[0]
            resolved = posixpath.normpath("/srv/public/" + name)
            if resolved in VFS:
                return self._send(200, VFS[resolved].encode(), "text/plain")
            return self._json(404, {"error": "no such file", "resolved": resolved})

        # --- JSON APIs ---
        if path in ("/api/catalog",):
            return self._json(200, [{"id": p["id"], "title": p["title"], "price": p["price"], "sku": p["sku"]}
                                    for p in PRODUCTS if p["id"] != 4])
        if path in ("/api/users", "/api/users.php"):
            return self._json(200, USERS)
        if path == "/api/account/profile":
            with ROLE_LOCK:
                return self._json(200, {"role": ROLE_STATE["v"]})
        if path == "/api/account/profile-secure":
            with ROLE_LOCK:
                return self._json(200, {"role": ROLE_STATE["s"]})
        if path == "/api/privileged":
            auth = self.headers.get("Authorization", "")
            bm = re.match(r"(?i)bearer\s+(\S+)", auth)
            token = bm.group(1) if bm else None
            if token and token in set(API_KEYS.values()):
                return self._json(200, {"privileged": True, "users": USERS})
            return self._json(401, {"error": "bearer token required"})

        m = re.match(r"^/order\.php$", path)
        if m or path == "/api/orders":  # IDOR
            oid = q.get("id", [""])[0]
            o = ORDERS.get(oid)
            return self._json(200 if o else 404, o or {"error": "not found"})

        if path in ("/api/search",):
            term = q.get("q", [""])[0]
            if term.count("'") % 2 == 1:
                return self._send(500, (
                    "<b>Warning</b>: mysqli_query(): You have an error in your SQL syntax near "
                    f"\"'{term}'\" at line 1 in <b>/var/www/html/includes/db.php</b> on line 51\n").encode(),
                    "text/html")
            norm = term.lower().replace(" ", "")
            if "or'1'='1" in norm or "or1=1" in norm:
                rows = PRODUCTS
            elif "and'1'='2" in norm or "and1=2" in norm:
                rows = []
            else:
                rows = [p for p in PRODUCTS if term.lower() in p["title"].lower()]
            return self._json(200, rows)
        if path in ("/api/products",):
            term = q.get("q", [""])[0]
            return self._json(200, [p for p in PRODUCTS if term.lower() in p["title"].lower()])

        if path in ("/api/checkout",):
            item = q.get("item", ["1"])[0]
            try:
                price = float(q.get("price", ["0"])[0] or 0)
            except ValueError:
                price = 0.0
            return self._json(200, {"item": item, "charged": price, "list_price": 48.00, "status": "ok"})
        if path in ("/api/checkout-secure",):
            return self._json(200, {"item": q.get("item", ["1"])[0], "charged": 48.00, "list_price": 48.00, "status": "ok"})

        if path in ("/api/data",):
            origin = self.headers.get("Origin", "https://evil.example")
            return self._json(200, {"data": [1, 2, 3]}, extra={
                "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})

        if path in ("/api/crash",):
            return self._php_fatal('PDOException: SQLSTATE[42000]: Syntax error or access violation')

        return self._json(404, {"error": "not found"})

    # --- helpers ---
    def _send_text_page(self, title, text):
        # used only to shape an LFI include of a non-HTML file into a page
        return render("page", title="include", body=f"<pre>{html.escape(text)}</pre>")

    def _phpinfo(self) -> str:
        return (
            "<html><head><title>phpinfo()</title></head><body>"
            f"<h1>PHP Version {PHP_VERSION}</h1>"
            "<table border=1 cellpadding=4>"
            f"<tr><td>System</td><td>Linux northwind-web 6.1.0-northwind x86_64</td></tr>"
            f"<tr><td>Server API</td><td>FPM/FastCGI</td></tr>"
            f"<tr><td>Loaded Configuration File</td><td>/etc/php/8.1/fpm/php.ini</td></tr>"
            f"<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>"
            f"<tr><td>session.upload_progress.enabled</td><td>On</td></tr>"
            f"<tr><td>disable_functions</td><td><i>no value</i></td></tr>"
            f"<tr><td>DATABASE_URL</td><td>mysql://admin:{DEMO_SECRET}@db.internal.northwind.test/prod</td></tr>"
            "</table></body></html>"
        )


def main():
    ap = argparse.ArgumentParser(description="Northwind Store — deliberately-vulnerable demo app.")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8099")))
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"Northwind Store (nginx/{SERVER_BANNER.split('/')[1]} + PHP {PHP_VERSION}) on "
          f"http://{a.host}:{a.port}  — intentionally vulnerable, do not expose", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
