"""Intentionally vulnerable security-scanner benchmark.

All identities, invoices, products and exposed configuration values are synthetic.
Do not put production data in this service or deploy alongside production apps.
"""

from __future__ import annotations

import html
import json
import os
import secrets
import sqlite3
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
FIXTURES = (ROOT / "fixtures").resolve()
DEMO_USERS = {
    "alice@example.test": {"password": "alice-demo-2026", "name": "Alice", "account": "alice"},
    "bob@example.test": {"password": "bob-demo-2026", "name": "Bob", "account": "bob"},
}
INVOICES = {
    "1001": {"id": "1001", "owner": "alice", "description": "Synthetic Alice invoice", "amount": 120},
    "2002": {"id": "2002", "owner": "bob", "description": "Synthetic Bob invoice", "amount": 240},
}
SESSIONS: dict[str, str] = {}
PREFERENCES = {"alice": "alice@example.test", "bob": "bob@example.test"}
LOCK = threading.Lock()


def html_page(title: str, content: str) -> bytes:
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>{html.escape(title)}</title></head><body>"
            "<p><a href='/'>Home</a> | <a href='/login'>Sign in</a> | "
            "<a href='/preferences'>Preferences</a></p>"
            f"<h1>{html.escape(title)}</h1>{content}</body></html>").encode("utf-8")


def form_value(values: dict[str, list[str]], key: str, default: str = "") -> str:
    return values.get(key, [default])[0]


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "BenchmarkDemo"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        # Log only request method/status, not URL queries or fake passwords.
        # The app is disposable, so logs should not be sent to production analytics.
        return

    def send(self, status: int, body: bytes | str, content_type: str = "text/html; charset=utf-8", headers: dict[str, str] | None = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        # INTENTIONALLY missing important browser security headers (B01).
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, status: int = HTTPStatus.FOUND, headers: dict[str, str] | None = None) -> None:
        self.send(status, "", headers={"Location": location, **(headers or {})})

    def current_user(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            session_id = cookie.get("session")
            if session_id:
                with LOCK:
                    return SESSIONS.get(session_id.value)
        except Exception:
            return None
        return None

    def require_login(self) -> str | None:
        user = self.current_user()
        if user is None:
            self.send(401, html_page("Sign in required", "<p>Please use a demo account.</p>"))
        return user

    def do_GET(self) -> None:  # noqa: N802
        target = urlsplit(self.path)
        path = target.path
        qs = parse_qs(target.query, keep_blank_values=True)

        if path == "/":
            links = (
                "<ul>"
                "<li><a href='/search?q=notebook'>Search</a></li>"
                "<li><a href='/catalog?id=1'>Product catalog</a></li>"
                "<li><a href='/go?next=%2F'>Visit another page</a></li>"
                "<li><a href='/files?name=guide.txt'>Download document</a></li>"
                "<li><a href='/api/profile'>My profile (JSON)</a></li>"
                "<li><a href='/api/invoice?id=1001'>My invoice (JSON)</a></li>"
                "<li><a href='/preferences'>My preferences</a></li>"
                "</ul>"
            )
            self.send(200, html_page("Sample Portal", "<p>This is a test-only portal containing synthetic data.</p>" + links))
            return

        if path == "/login":
            self.send(200, html_page("Sign in", (
                "<form action='/login' method='post'>"
                "<label>Email <input name='email'></label>"
                "<label>Password <input type='password' name='password'></label>"
                "<button type='submit'>Sign in</button></form>"
            )))
            return

        if path == "/account":
            user = self.require_login()
            if user is not None:
                self.send(200, html_page("My account", f"<p>Signed in as {html.escape(user)}.</p>"))
            return

        if path == "/search":
            # B06: User query is placed directly in HTML without escaping (reflected XSS).
            query = form_value(qs, "q")[:500]
            self.send(200, html_page("Search", (
                "<form><input name='q' value=''><button>Search</button></form>"
                f"<p>Search results for: {query}</p>"
            )))
            return

        if path == "/catalog":
            # B07: Deliberately concatenated SQL with an entirely disposable SQLite DB.
            product_id = form_value(qs, "id", "1")[:160]
            try:
                with sqlite3.connect(":memory:") as db:
                    db.execute("CREATE TABLE products (id TEXT, name TEXT, price INT)")
                    db.executemany("INSERT INTO products VALUES (?, ?, ?)", [
                        ("1", "Notebook", 12), ("2", "Pen", 4), ("3", "Backpack", 40)
                    ])
                    began = time.monotonic()
                    db.set_progress_handler(lambda: 1 if time.monotonic() - began > 0.05 else 0, 200)
                    rows = db.execute(
                        "SELECT id, name, price FROM products WHERE id = '" + product_id + "' LIMIT 20"
                    ).fetchall()
                products = "".join(f"<li>{html.escape(str(n))}: {price}</li>" for _, n, price in rows)
                self.send(200, html_page("Catalog", "<p>Product records:</p><ul>" + products + "</ul>"))
            except sqlite3.Error:
                self.send(400, html_page("Invalid product", "<p>Unable to look up that product.</p>"))
            return

        if path == "/go":
            # B05: Unvalidated external redirect.
            self.redirect(form_value(qs, "next", "/")[:500])
            return

        if path == "/files":
            # B08: Traversal from fixtures/public into fixtures/private succeeds,
            # but the resolved path is STRICTLY confined to disposable fixture data.
            name = form_value(qs, "name", "guide.txt")[:200]
            candidate = (FIXTURES / "public" / name).resolve()
            if not candidate.is_relative_to(FIXTURES):
                self.send(403, "Restricted to demo fixture directory", "text/plain; charset=utf-8")
            elif not candidate.is_file():
                self.send(404, "No such demo fixture", "text/plain; charset=utf-8")
            else:
                self.send(200, candidate.read_bytes(), "text/plain; charset=utf-8")
            return

        if path == "/.env":
            # B03: A publicly exposed *fake* environment file, no genuine secrets.
            self.send(200, "# BENCHMARK_FAKE_ONLY\nAPP_ENV=demo\nFAKE_API_KEY=TEST_KEY_NOT_REAL_000\n", "text/plain; charset=utf-8")
            return

        if path == "/api/profile":
            user = self.require_login()
            if user is not None:
                # B04: Arbitrary Origin is reflected while allowing credentials.
                origin = self.headers.get("Origin", "")
                headers = {"Access-Control-Allow-Origin": origin,
                           "Access-Control-Allow-Credentials": "true"} if origin else {}
                self.send(200, json.dumps({"user": user, "plan": "demo"}), "application/json", headers)
            return

        if path == "/api/invoice":
            user = self.require_login()
            if user is not None:
                invoice_id = form_value(qs, "id", "1001")
                invoice = INVOICES.get(invoice_id)
                if invoice is None:
                    self.send(404, "{}", "application/json")
                else:
                    # B09: Missing invoice owner validation (IDOR / broken access control).
                    self.send(200, json.dumps(invoice), "application/json")
            return

        if path == "/preferences":
            user = self.require_login()
            if user is not None:
                with LOCK:
                    contact = PREFERENCES[user]
                self.send(200, html_page("Preferences", (
                    f"<p>Preferred contact: {html.escape(contact)}</p>"
                    "<form action='/preferences' method='post'>"
                    "<label>Contact <input name='contact'></label>"
                    "<button type='submit'>Save</button></form>"
                )))
            return

        if path == "/preferences/update":
            # B10: A state-changing GET request, intentionally no anti-CSRF token.
            user = self.require_login()
            if user is not None:
                with LOCK:
                    PREFERENCES[user] = form_value(qs, "contact", "")[:150]
                self.redirect("/preferences", HTTPStatus.SEE_OTHER)
            return

        self.send(404, html_page("Not found", "<p>That page does not exist.</p>"))

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 <= length <= 4096:
            self.send(413, "Request too large", "text/plain; charset=utf-8")
            return
        data = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
        if path == "/login":
            email = form_value(data, "email")
            password = form_value(data, "password")
            if email in DEMO_USERS and secrets.compare_digest(DEMO_USERS[email]["password"], password):
                session_id = secrets.token_urlsafe(32)
                with LOCK:
                    SESSIONS[session_id] = DEMO_USERS[email]["account"]
                # B02: Session cookie deliberately lacks Secure, HttpOnly, SameSite.
                self.redirect("/account", HTTPStatus.SEE_OTHER,
                              {"Set-Cookie": f"session={session_id}; Path=/"})
            else:
                self.send(401, html_page("Sign in failed", "<p>Incorrect demo credentials.</p>"))
            return

        if path == "/preferences":
            user = self.require_login()
            if user is not None:
                # B10: No CSRF token. Synthetic preference only.
                with LOCK:
                    PREFERENCES[user] = form_value(data, "contact", "")[:150]
                self.redirect("/preferences", HTTPStatus.SEE_OTHER)
            return

        self.send(404, "Unknown endpoint", "text/plain; charset=utf-8")

    def do_OPTIONS(self) -> None:  # noqa: N802
        if urlsplit(self.path).path == "/api/profile":
            origin = self.headers.get("Origin", "")
            self.send(204, b"", "text/plain", {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": self.headers.get("Access-Control-Request-Headers", "Content-Type"),
            })
        else:
            self.send(404, "", "text/plain")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer((host, port), DemoHandler)
    print(f"Benchmark demo running at http://{host}:{port}/", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
