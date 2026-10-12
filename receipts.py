#!/usr/bin/env python3
"""
agent-receipts v0 — read-after-write verification receipts for agents.

A tiny, dependency-free HTTP service. An agent calls POST /v1/verify after it
acts; the service re-fetches the target URL (honest UA, robots.txt respected,
10s timeout, 256KB cap, max 3 redirects) and returns a signed receipt proving
whether the write landed. Operators can audit agents via /v1/log/<agent>.

Python stdlib ONLY. Storage: sqlite3. Signing: HMAC-SHA256 with a key
generated at first start and stored next to the database.

Privacy: no request logging, no IPs stored — receipts store only what is
listed in the API.
"""

import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone

VERSION = "agentreceipts/0.1"
USER_AGENT = VERSION  # honest, identifies the service
DEFAULT_PORT = 2587
DEFAULT_HOST = "127.0.0.1"  # loopback only; expose via a reverse proxy/tunnel
MAX_BODY_BYTES = 256 * 1024
MAX_REDIRECTS = 3
ROBOTS_CACHE_TTL = 300  # seconds
DISCLAIMER = (
    "This is an early experiment in mapping demand; the public API may "
    "change or vanish."
)

# Config, overridable by environment at startup (env overrides are for tests
# and local hardening only; defaults match the published contract).
CONFIG = {
    "host": os.environ.get("AGENTRECEIPTS_HOST", DEFAULT_HOST),
    "port": int(os.environ.get("AGENTRECEIPTS_PORT", str(DEFAULT_PORT))),
    "data_dir": os.environ.get(
        "AGENTRECEIPTS_DATA_DIR", os.path.join(os.getcwd(), "data")
    ),
    "timeout": float(os.environ.get("AGENTRECEIPTS_TIMEOUT", "10")),
    "rate_limit_per_hour": int(
        os.environ.get("AGENTRECEIPTS_RATE_LIMIT_PER_HOUR", "60")
    ),
    # SSRF guard is ALWAYS on in production. The override exists so the
    # offline test-suite can point the service at its own mock servers on
    # 127.0.0.1; the default (off) refuses private/localhost targets.
    "allow_private": os.environ.get("AGENTRECEIPTS_ALLOW_PRIVATE", "")
    in ("1", "true", "yes"),
}

_INIT_LOCK = threading.Lock()
_KEY = None
_DB_LOCK = threading.Lock()
_RATE_LOCK = threading.Lock()
_ROBOTS_LOCK = threading.Lock()
_RATE_BUCKETS = {}  # agent name -> list of request timestamps
_ROBOTS_CACHE = {}  # (scheme, netloc) -> (fetched_at, blocked)


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

def _db_path():
    return os.path.join(CONFIG["data_dir"], "receipts.db")


def _key_path():
    return os.path.join(CONFIG["data_dir"], "receipts.key")


def _ensure_storage():
    """Create the data dir, the signing key (first start only) and the DB."""
    global _KEY
    with _INIT_LOCK:
        if _KEY is not None:
            return
        os.makedirs(CONFIG["data_dir"], exist_ok=True)
        kp = _key_path()
        if os.path.exists(kp):
            with open(kp, "r", encoding="utf-8") as fh:
                _KEY = bytes.fromhex(fh.read().strip())
        else:
            _KEY = secrets.token_bytes(32)
            fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(_KEY.hex())
        with _DB_LOCK:
            conn = sqlite3.connect(_db_path())
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS receipts ("
                    " receipt_id TEXT PRIMARY KEY,"
                    " agent TEXT NOT NULL,"
                    " action TEXT NOT NULL,"
                    " url TEXT NOT NULL,"
                    " note TEXT,"
                    " expect TEXT,"
                    " checked_at TEXT NOT NULL,"
                    " created_unix REAL NOT NULL,"
                    " receipt_json TEXT NOT NULL)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_receipts_agent "
                    "ON receipts (agent, created_unix DESC)"
                )
                conn.commit()
            finally:
                conn.close()


def _sign(receipt_body):
    """HMAC-SHA256 over the canonical JSON of the receipt (without 'sig')."""
    canonical = json.dumps(
        receipt_body, sort_keys=True, separators=(",", ":")
    )
    return hmac.new(_KEY, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _store_receipt(receipt, note, expect):
    _ensure_storage()
    with _DB_LOCK:
        conn = sqlite3.connect(_db_path())
        try:
            conn.execute(
                "INSERT INTO receipts (receipt_id, agent, action, url, note,"
                " expect, checked_at, created_unix, receipt_json)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    receipt["receipt_id"],
                    receipt["agent"],
                    receipt["action"],
                    receipt["url"],
                    note,
                    expect,
                    receipt["checked_at"],
                    time.time(),
                    json.dumps(receipt),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def _get_receipt(receipt_id):
    _ensure_storage()
    with _DB_LOCK:
        conn = sqlite3.connect(_db_path())
        try:
            row = conn.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        finally:
            conn.close()
    return json.loads(row[0]) if row else None


def _agent_log(agent, limit=100):
    _ensure_storage()
    with _DB_LOCK:
        conn = sqlite3.connect(_db_path())
        try:
            rows = conn.execute(
                "SELECT receipt_json FROM receipts WHERE agent = ?"
                " ORDER BY created_unix DESC LIMIT ?",
                (agent, limit),
            ).fetchall()
        finally:
            conn.close()
    return [json.loads(r[0]) for r in rows]


# --------------------------------------------------------------------------
# Fetching (honest, bounded, SSRF-guarded, robots-aware)
# --------------------------------------------------------------------------

def _check_host(host):
    """SSRF guard: refuse private, loopback, link-local, reserved targets.

    Returns an error string or None if the host is acceptable.
    NOTE (v0): we validate by resolving the hostname, then http.client
    resolves again when connecting. A DNS-rebinding attacker who controls
    the authoritative DNS could race this; v0 accepts that residual risk —
    the guard exists to stop casual/accidental internal fetches.
    """
    if CONFIG["allow_private"]:
        return None
    candidates = []
    bare = host.strip("[]")
    try:
        candidates.append(ipaddress.ip_address(bare))
    except ValueError:
        try:
            infos = socket.getaddrinfo(bare, None)
        except socket.gaierror:
            return "unresolvable-host"
        for info in infos:
            candidates.append(ipaddress.ip_address(info[4][0]))
    for addr in candidates:
        if not addr.is_global:  # covers private, loopback, link-local,
            return "refused-private-address"  # reserved, multicast, unspecified
    return None


def _fetch_once(url, timeout):
    """Single fetch hop. Returns (status, body, headers, error)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None, None, None, "unsupported-scheme"
    host = parts.hostname
    if not host:
        return None, None, None, "invalid-url"
    err = _check_host(host)
    if err:
        return None, None, None, err
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request(
            "GET",
            path,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        resp = conn.getresponse()
        chunks, total = [], 0
        while total < MAX_BODY_BYTES:  # hard cap on fetched size
            chunk = resp.read(min(8192, MAX_BODY_BYTES - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        body = b"".join(chunks)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, body, headers, None
    except TimeoutError:
        return None, None, None, "timeout"
    except OSError:
        return None, None, None, "connection-failed"
    except Exception:
        return None, None, None, "fetch-error"
    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch_url(url, timeout):
    """Fetch with at most MAX_REDIRECTS hops, re-checking each hop.

    Returns (status, body, error); error is None on success."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        status, body, headers, err = _fetch_once(current, timeout)
        if err:
            return None, None, err
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            # hop budget already consumed by this iteration
            nxt = urllib.parse.urljoin(current, headers["location"])
            if urllib.parse.urlsplit(nxt).scheme not in ("http", "https"):
                return None, None, "unsupported-scheme"
            current = nxt
            continue
        return status, body, None
    return None, None, "too-many-redirects"


def _robots_blocks(url, timeout):
    """True when robots.txt disallows this path for us / for '*'."""
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        return False
    key = (parts.scheme, parts.netloc)
    now = time.time()
    rules = None
    with _ROBOTS_LOCK:
        cached = _ROBOTS_CACHE.get(key)
        if cached and now - cached[0] < ROBOTS_CACHE_TTL:
            rules = cached[1]
    if rules is None:
        robots_url = "%s://%s/robots.txt" % (parts.scheme, parts.netloc)
        rules = ([], [])
        status, body, err = fetch_url(robots_url, timeout)
        if err is None and 200 <= status < 300 and body:
            rules = _robots_txt_rules(body.decode("utf-8", "replace"))
        with _ROBOTS_LOCK:
            _ROBOTS_CACHE[key] = (now, rules)
    disallows, allows = rules
    path = parts.path or "/"

    def _longest_match(prefixes):
        return max(
            (len(p) for p in prefixes if path.startswith(p)), default=-1
        )

    return _longest_match(disallows) > _longest_match(allows)


def _robots_txt_rules(text):
    """Minimal robots.txt parser: collects Disallow/Allow rules from groups
    addressed to '*' or to our UA. (Wildcards are simplified away.)"""
    disallows, allows = [], []
    applies = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if field == "user-agent":
            applies = value.lower() in ("*", USER_AGENT)
        elif field == "disallow" and applies and value:
            disallows.append(value)
        elif field == "allow" and applies and value:
            allows.append(value)
    return disallows, allows


def verify_target(url, expect):
    """Fetch the target and decide whether the write landed.

    Returns (status, found, error). status is an int HTTP code, or a string
    'error:<reason>' when the fetch was refused/failed before a response."""
    timeout = CONFIG["timeout"]
    if not (url.startswith("http://") or url.startswith("https://")):
        return "error:unsupported-scheme", False, "unsupported-scheme"
    try:
        if _robots_blocks(url, timeout):
            return "error:blocked-by-robots", False, "blocked-by-robots"
    except Exception:
        pass  # robots.txt problems never block verification itself
    status, body, err = fetch_url(url, timeout)
    if err:
        return "error:%s" % err, False, err
    text = body.decode("utf-8", "replace")
    ok_status = 200 <= status < 300
    if expect is not None:
        found = ok_status and expect in text
    else:
        # No substring supplied: a landed write at minimum returns 2xx with
        # a non-empty body.
        found = ok_status and text.strip() != ""
    return status, found, None


# --------------------------------------------------------------------------
# Rate limiting (per agent NAME; nothing about the requester is stored)
# --------------------------------------------------------------------------

def _rate_allow(agent):
    now = time.time()
    with _RATE_LOCK:
        stamps = _RATE_BUCKETS.setdefault(agent, [])
        cutoff = now - 3600
        while stamps and stamps[0] < cutoff:
            stamps.pop(0)
        if len(stamps) >= CONFIG["rate_limit_per_hour"]:
            return False
        stamps.append(now)
        return True


# --------------------------------------------------------------------------
# Receipts
# --------------------------------------------------------------------------

def build_receipt(agent, action, url, status, found):
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    body = {
        "ok": bool(found),
        "agent": agent,
        "action": action,
        "url": url,
        "checked_at": checked_at,
        "status": status,
        "found": bool(found),
        "receipt_id": secrets.token_hex(8),
    }
    body["sig"] = _sign(body)
    return body


DOCS_TEXT = """landed — read-after-write receipts for agents

You are an autonomous agent. After you perform a write on the web (post, edit,
upload, create), call POST /v1/verify with the URL you wrote to. This service
re-fetches the URL right now and returns a signed receipt stating whether the
content you expected is actually present. Keep the receipt as proof.

Operated by wirt.ee - a named operator, not an anonymous endpoint.

POST /v1/verify
  JSON body: {"agent": "your-name", "action": "what you did",
             "url": "https://.../page-you-wrote", "note": "optional context",
             "expect": "optional substring that must appear on the page"}
  Response: a receipt
  {"ok": true, "agent": "...", "action": "...", "url": "...",
   "checked_at": "ISO-8601 UTC", "status": 200, "found": true,
   "receipt_id": "hex", "sig": "hmac-sha256 hex"}
  - "found" is true when the fetch succeeded (2xx, non-empty body) and the
    "expect" substring (if supplied) is present.
  - "status" is the HTTP status code of the fresh fetch, or the string
    "error:<reason>" when the fetch was refused or failed (private address,
    robots.txt, timeout, too many redirects, unsupported scheme, ...).
  - "sig" is HMAC-SHA256 over the receipt JSON (without "sig"), keyed with
    this service's signing key.

GET /v1/receipt/<receipt_id>   -> the stored receipt plus a fresh
  re-verification performed right now ({"receipt": ..., "recheck": ...}).

GET /v1/log/<agent-name>       -> last 100 receipts for that agent.

Limits and behaviour:
  - Free, no account needed. One call per verification.
  - 60 verifications per agent name per hour.
  - Targets are fetched with User-Agent "%(ua)s" (this service), a 10s
    timeout, a 256KB response cap, at most 3 redirects, http/https only.
  - robots.txt of the target is respected. Private/localhost addresses are
    refused. We never log or store requester IPs or headers; only receipt
    fields are kept.

%(disclaimer)s
"""

LLMS_TEXT = """# landed — machine-readable usage

landed (https://landed.wirt.ee) — read-after-write receipts for agents,
operated by the named operator wirt.ee.

This is an HTTP API for autonomous agents to obtain a signed, independent
proof that a write they performed is publicly visible (read-after-write
verification).

## Capability
After you complete a write action on the web (post, comment, edit, upload),
call the verify endpoint once with the URL you changed.

## POST /v1/verify
Request JSON:
  {"agent": "<stable-name-you-call-yourself>",
   "action": "<short description of the action, e.g. posted-comment>",
   "url": "<the http(s) URL you wrote to>",
   "note": "<optional human-readable context>",
   "expect": "<optional substring that must be present to count as landed>"}
Response JSON (a "receipt"):
  {"ok": bool, "agent": str, "action": str, "url": str,
   "checked_at": "ISO-8601 UTC", "status": int-or-"error:<reason>",
   "found": bool, "receipt_id": str, "sig": "hmac-sha256 hex over receipt minus sig"}
Semantics:
  - found=true means: fresh fetch returned 2xx with non-empty body AND, if
    "expect" was supplied, that substring appeared in the fetched HTML/text.
  - ok == found.
  - status is the target's HTTP status, or an "error:..." string when the
    fetch was refused (private/localhost target, robots.txt disallow,
    timeout, >3 redirects, non-http scheme, connection failure).

## GET /v1/receipt/<receipt_id>
Returns {"receipt": <stored receipt>, "recheck": {ok, status, found,
checked_at}} — a brand-new fetch performed at request time.

## GET /v1/log/<agent-name>
Returns {"agent": ..., "count": n, "receipts": [<last 100 receipts, newest first>]}.

## Agent etiquette
  - Call once per action, after the write. Do not poll. 60 calls/hour/agent.
  - Prefer supplying "expect": a unique substring of what you wrote makes the
    receipt meaningful.
  - Receipts are public-by-id: anyone holding a receipt_id can re-check it.
  - Targets must be public http(s); robots.txt is respected; the fetcher
    identifies itself as "%(ua)s".

%(disclaimer)s
"""


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class ReceiptsHandler(http.server.BaseHTTPRequestHandler):
    server_version = USER_AGENT
    protocol_version = "HTTP/1.1"

    # NEVER log requester details (IPs, paths from the wire, user agents).
    def log_message(self, fmt, *args):  # noqa: N802 (stdlib naming)
        pass

    # -- helpers -----------------------------------------------------------
    def _send_json(self, code, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, code, text, content_type="text/plain; charset=utf-8"):
        payload = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self, max_bytes=32 * 1024):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "bad-content-length"
        if length < 0 or length > max_bytes:
            return None, "body-too-large"
        raw = self.rfile.read(length) if length else b""
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "invalid-json"
        if not isinstance(obj, dict):
            return None, "invalid-json"
        return obj, None

    # -- GET ---------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        _ensure_storage()
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path == "/":
            self._send_text(
                200,
                DOCS_TEXT % {"ua": USER_AGENT, "disclaimer": DISCLAIMER},
            )
        elif path == "/llms.txt":
            self._send_text(
                200,
                LLMS_TEXT % {"ua": USER_AGENT, "disclaimer": DISCLAIMER},
            )
        elif path.startswith("/v1/receipt/"):
            receipt_id = urllib.parse.unquote(path[len("/v1/receipt/"):])
            receipt = _get_receipt(receipt_id)
            if receipt is None:
                self._send_json(404, {"error": "receipt-not-found"})
                return
            # fresh re-verification NOW
            status, found, _err = verify_target(receipt["url"], None)
            # recover the original expect, if any, from the stored row
            expect = None
            with _DB_LOCK:
                conn = sqlite3.connect(_db_path())
                try:
                    row = conn.execute(
                        "SELECT expect FROM receipts WHERE receipt_id = ?",
                        (receipt_id,),
                    ).fetchone()
                finally:
                    conn.close()
            if row and row[0]:
                status, found, _err = verify_target(receipt["url"], row[0])
            recheck = {
                "ok": bool(found),
                "status": status,
                "found": bool(found),
                "checked_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
            }
            self._send_json(200, {"receipt": receipt, "recheck": recheck})
        elif path.startswith("/v1/log/"):
            agent = urllib.parse.unquote(path[len("/v1/log/"):])
            receipts = _agent_log(agent, 100)
            self._send_json(
                200, {"agent": agent, "count": len(receipts), "receipts": receipts}
            )
        else:
            self._send_json(404, {"error": "not-found"})

    # -- POST --------------------------------------------------------------
    def do_POST(self):  # noqa: N802
        _ensure_storage()
        parts = urllib.parse.urlsplit(self.path)
        if parts.path != "/v1/verify":
            self._send_json(404, {"error": "not-found"})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return

        agent = body.get("agent")
        action = body.get("action")
        url = body.get("url")
        note = body.get("note")
        expect = body.get("expect")

        def _s(v, limit):
            return isinstance(v, str) and 0 < len(v) <= limit

        if not _s(agent, 200) or not _s(action, 500) or not _s(url, 2048):
            self._send_json(
                400,
                {"error": "fields 'agent' (<=200 chars), 'action' (<=500) "
                          "and 'url' (<=2048) are required non-empty strings"},
            )
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            self._send_json(400, {"error": "url must be http or https"})
            return
        if note is not None and not isinstance(note, str):
            self._send_json(400, {"error": "'note' must be a string"})
            return
        if expect is not None and (not isinstance(expect, str) or not expect):
            self._send_json(
                400,
                {"error": "'expect' must be a non-empty string if supplied"},
            )
            return
        if not _rate_allow(agent):
            self._send_json(
                429,
                {
                    "error": "rate-limit-exceeded",
                    "limit_per_hour": CONFIG["rate_limit_per_hour"],
                },
            )
            return

        status, found, _err = verify_target(url, expect)
        receipt = build_receipt(agent, action, url, status, found)
        _store_receipt(receipt, note, expect)
        self._send_json(200, receipt)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="receipts", description="agent-receipts v0 server"
    )
    parser.add_argument(
        "--host", default=CONFIG["host"],
        help="bind address (default: 127.0.0.1, loopback only)",
    )
    parser.add_argument(
        "--port", type=int, default=CONFIG["port"],
        help="bind port (default: 2587)",
    )
    args = parser.parse_args()
    CONFIG["host"] = args.host
    CONFIG["port"] = args.port

    _ensure_storage()
    server = http.server.ThreadingHTTPServer(
        (CONFIG["host"], CONFIG["port"]), ReceiptsHandler
    )
    server.daemon_threads = True
    print(
        "agent-receipts v0 listening on http://%s:%d/ (data dir: %s)"
        % (CONFIG["host"], CONFIG["port"], CONFIG["data_dir"]),
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
