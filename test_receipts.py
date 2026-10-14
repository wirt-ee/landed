#!/usr/bin/env python3
"""
Offline test-suite for agent-receipts v0 (receipts.py).

All tests run against local mock servers on 127.0.0.1 — no network access
required. The service's SSRF guard refuses private/localhost targets in
production; the tests enable AGENTRECEIPTS_ALLOW_PRIVATE=1 so the service can
fetch the mock target, and the deliberately hostile tests flip the guard back
to its production default (off) to prove 127.0.0.1 is refused.

Run:  python3 test_receipts.py
"""

import http.client
import http.server
import json
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Configure BEFORE importing receipts: test-only overrides.
_TMP = tempfile.mkdtemp(prefix="agentreceipts-test-")
os.environ["AGENTRECEIPTS_ALLOW_PRIVATE"] = "1"  # so we can fetch the mocks
os.environ["AGENTRECEIPTS_TIMEOUT"] = "0.5"     # fast timeout test
os.environ["AGENTRECEIPTS_RATE_LIMIT_PER_HOUR"] = "3"
os.environ["AGENTRECEIPTS_DATA_DIR"] = _TMP

import receipts  # noqa: E402

MARKER = "agentreceipts-marker-9f1c2d"
SECRET_MARKER = "super-secret-42"
DISCLAIMER = (
    "This is an early experiment in mapping demand; the public API may "
    "change or vanish."
)


# --------------------------------------------------------------------------
# Mock target server (the thing agents claim to have written to)
# --------------------------------------------------------------------------

class MockTargetHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: N802
        pass

    def _respond(self, code, text, extra_headers=None):
        payload = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            # the service intentionally stops reading at its 256KB cap
            pass

    def do_GET(self):  # noqa: N802
        path = self.path
        if path == "/robots.txt":
            self._respond(200, "User-agent: *\nDisallow: /private/\n")
        elif path == "/page":
            self._respond(200, "<html><body>hello " + MARKER + "</body></html>")
        elif path == "/gone":
            self._respond(200, "<html><body>nothing relevant here</body></html>")
        elif path == "/empty":
            self._respond(200, "")
        elif path == "/missing":
            self._respond(404, "<html><body>404 page</body></html>")
        elif path == "/private/secret":
            self._respond(200, "<html><body>" + SECRET_MARKER + "</body></html>")
        elif path == "/slow":
            time.sleep(2.0)  # longer than the 0.5s test timeout
            self._respond(200, "late " + MARKER)
        elif path == "/redirect":
            self._respond(302, "", {"Location": "/page"})
        elif path == "/redirect-loop":
            self._respond(302, "", {"Location": "/redirect-loop"})
        elif path == "/redirect-2":
            self._respond(302, "", {"Location": "/redirect-3"})
        elif path == "/redirect-3":
            self._respond(302, "", {"Location": "/redirect-4"})
        elif path == "/redirect-4":
            self._respond(302, "", {"Location": "/page"})
        elif path == "/big":
            body = "x" * (300 * 1024) + " " + MARKER  # marker beyond 256KB cap
            self._respond(200, body)
        else:
            self._respond(404, "not found")


_MOCK = None
_SERVICE = None
MOCK_PORT = 0
SERVICE_PORT = 0


class QuietServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer that ignores benign connection resets
    (clients closing keep-alive sockets during teardown)."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


def _start_server(handler_cls):
    srv = QuietServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def setUpModule():  # noqa: N802
    global _MOCK, _SERVICE, MOCK_PORT, SERVICE_PORT
    _MOCK = _start_server(MockTargetHandler)
    _SERVICE = _start_server(receipts.ReceiptsHandler)
    MOCK_PORT = _MOCK.server_address[1]
    SERVICE_PORT = _SERVICE.server_address[1]


def tearDownModule():  # noqa: N802
    _MOCK.shutdown()
    _SERVICE.shutdown()


def _url(path):
    return "http://127.0.0.1:%d%s" % (MOCK_PORT, path)


def _request(method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", SERVICE_PORT, timeout=15)
    try:
        headers = {}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            parsed = raw.decode("utf-8", "replace")
        return resp.status, parsed
    finally:
        conn.close()


def _verify(agent, action, url, expect=None, note=None):
    body = {"agent": agent, "action": action, "url": url}
    if expect is not None:
        body["expect"] = expect
    if note is not None:
        body["note"] = note
    return _request("POST", "/v1/verify", body)


class TestVerify(unittest.TestCase):
    def test_found_with_expect(self):
        code, r = _verify("t-agent", "posted-comment", _url("/page"), expect=MARKER)
        self.assertEqual(code, 200)
        self.assertTrue(r["ok"])
        self.assertTrue(r["found"])
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["agent"], "t-agent")
        self.assertEqual(r["url"], _url("/page"))
        self.assertTrue(r["receipt_id"])
        self.assertTrue(r["sig"])
        self.assertEqual(
            set(r.keys()),
            {"ok", "agent", "action", "url", "checked_at", "status",
             "found", "receipt_id", "digest", "sig", "sig_ed25519"},
        )

    def test_found_without_expect_nonempty_2xx(self):
        code, r = _verify("t-agent2", "edit", _url("/page"))
        self.assertEqual(code, 200)
        self.assertTrue(r["found"])

    def test_not_found_expect_absent(self):
        code, r = _verify("t-agent3", "posted", _url("/gone"), expect=MARKER)
        self.assertEqual(code, 200)
        self.assertFalse(r["found"])
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], 200)

    def test_empty_2xx_body_not_found_without_expect(self):
        code, r = _verify("t-agent4", "posted", _url("/empty"))
        self.assertEqual(code, 200)
        self.assertFalse(r["found"])

    def test_http_404(self):
        code, r = _verify("t-agent5", "posted", _url("/missing"))
        self.assertEqual(code, 200)
        self.assertFalse(r["found"])
        self.assertEqual(r["status"], 404)

    def test_robots_blocked(self):
        code, r = _verify(
            "t-agent6", "posted-secret", _url("/private/secret"),
            expect=SECRET_MARKER,
        )
        self.assertEqual(code, 200)
        self.assertFalse(r["found"])
        self.assertEqual(r["status"], "error:blocked-by-robots")

    def test_timeout(self):
        code, r = _verify("t-agent7", "posted", _url("/slow"), expect=MARKER)
        self.assertEqual(code, 200)
        self.assertFalse(r["found"])
        self.assertEqual(r["status"], "error:timeout")

    def test_redirect_followed(self):
        code, r = _verify("t-agent8", "posted", _url("/redirect"), expect=MARKER)
        self.assertEqual(code, 200)
        self.assertTrue(r["found"])
        self.assertEqual(r["status"], 200)

    def test_too_many_redirects(self):
        # /redirect-2 -> 3 -> 4 -> /page: 3 hops allowed, so this must land.
        code, r = _verify("t-agent9a", "posted", _url("/redirect-2"), expect=MARKER)
        self.assertTrue(r["found"])
        # self-loop never resolves within 3 hops
        code, r = _verify("t-agent9", "posted", _url("/redirect-loop"))
        self.assertEqual(code, 200)
        self.assertFalse(r["found"])
        self.assertEqual(r["status"], "error:too-many-redirects")

    def test_unsupported_scheme_rejected(self):
        # non-http(s) schemes are refused at the API level (HTTP 400)
        code, out = _request(
            "POST", "/v1/verify",
            {"agent": "t-agent10", "action": "y", "url": "ftp://example.com/x"},
        )
        self.assertEqual(code, 400)
        self.assertEqual(out["error"], "url must be http or https")

    def test_body_size_cap_256kb(self):
        # marker sits beyond the 256KB cap -> must not be found
        code, r = _verify("t-agent11", "posted", _url("/big"), expect=MARKER)
        self.assertEqual(code, 200)
        self.assertFalse(r["found"])

    def test_honest_user_agent_used(self):
        class UAMock(MockTargetHandler):
            seen_ua = None

            def do_GET(self):  # noqa: N802
                if self.path == "/ua":
                    UAMock.seen_ua = self.headers.get("User-Agent")
                    self._respond(200, MARKER)
                else:
                    super().do_GET()

        srv = _start_server(UAMock)
        try:
            port = srv.server_address[1]
            old = receipts.CONFIG["allow_private"]
            receipts.CONFIG["allow_private"] = True
            code, r = _verify(
                "t-agent12", "posted", "http://127.0.0.1:%d/ua" % port,
                expect=MARKER,
            )
            self.assertTrue(r["found"])
            self.assertEqual(UAMock.seen_ua, "agentreceipts/0.1")
        finally:
            receipts.CONFIG["allow_private"] = old
            srv.shutdown()
            srv.server_close()
            receipts._ROBOTS_CACHE.clear()


class TestHostileSSRF(unittest.TestCase):
    """Deliberately hostile: prove the guard refuses localhost/private IPs."""

    def _assert_refused(self, url):
        old = receipts.CONFIG["allow_private"]
        receipts.CONFIG["allow_private"] = False  # production default
        try:
            agent = "t-hostile-%d" % int(time.time() * 1000000 % 10**12)
            code, r = _verify(agent, "posted", url, expect=MARKER)
            self.assertEqual(code, 200)  # endpoint works, but fetch refused
            self.assertFalse(r["found"])
            self.assertEqual(r["status"], "error:refused-private-address")
        finally:
            receipts.CONFIG["allow_private"] = old
            # restore caches: with the guard off, robots lookups failed and
            # must not poison results for later tests on the same netloc
            receipts._ROBOTS_CACHE.clear()

    def test_refuses_loopback_ip(self):
        self._assert_refused(_url("/page"))

    def test_refuses_localhost_name(self):
        self._assert_refused("http://localhost:%d/page" % MOCK_PORT)

    def test_refuses_private_range(self):
        self._assert_refused("http://10.0.0.1/page")

    def test_refuses_link_local(self):
        self._assert_refused("http://169.254.169.254/latest/meta-data/")

    def test_refuses_ipv6_loopback(self):
        self._assert_refused("http://[::1]:%d/page" % MOCK_PORT)


class TestRateLimit(unittest.TestCase):
    def test_rate_limited_after_limit(self):
        agent = "rl-agent-%d" % int(time.time() * 1000 % 1e9)
        for i in range(3):  # limit is 3/hour for tests
            code, r = _verify(agent, "posted", _url("/gone"))
            self.assertEqual(code, 200)
        code, r = _verify(agent, "posted", _url("/gone"))
        self.assertEqual(code, 429)
        self.assertEqual(r["error"], "rate-limit-exceeded")

    def test_limit_is_per_agent_name(self):
        agent1 = "rl-per-a-%d" % int(time.time() * 1000 % 1e9)
        agent2 = "rl-per-b-%d" % int(time.time() * 1000 % 1e9)
        for i in range(3):
            _verify(agent1, "posted", _url("/gone"))
        code, _ = _verify(agent2, "posted", _url("/gone"))
        self.assertEqual(code, 200)


class TestReceiptAndLog(unittest.TestCase):
    def test_receipt_recheck(self):
        code, r = _verify("log-agent-rc", "posted", _url("/page"), expect=MARKER)
        rid = r["receipt_id"]
        code, out = _request("GET", "/v1/receipt/%s" % rid)
        self.assertEqual(code, 200)
        self.assertEqual(out["receipt"]["receipt_id"], rid)
        self.assertTrue(out["recheck"]["found"])
        self.assertTrue(out["recheck"]["ok"])
        self.assertEqual(out["recheck"]["status"], 200)
        self.assertIn("checked_at", out["recheck"])

    def test_receipt_not_found(self):
        code, out = _request("GET", "/v1/receipt/nonexistent0000")
        self.assertEqual(code, 404)

    def test_log_returns_receipts_newest_first(self):
        agent = "log-agent-%d" % int(time.time() * 1000 % 1e9)
        ids = []
        for i in range(3):
            _, r = _verify(agent, "posted-%d" % i, _url("/page"), expect=MARKER)
            ids.append(r["receipt_id"])
            time.sleep(0.05)
        code, out = _request("GET", "/v1/log/%s" % agent)
        self.assertEqual(code, 200)
        self.assertEqual(out["agent"], agent)
        self.assertEqual(out["count"], 3)
        got = [rc["receipt_id"] for rc in out["receipts"]]
        self.assertEqual(got, list(reversed(ids)))  # newest first

    def test_log_empty(self):
        code, out = _request("GET", "/v1/log/nobody-here")
        self.assertEqual(code, 200)
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["receipts"], [])


class TestSignature(unittest.TestCase):
    def test_sig_is_valid_hmac(self):
        import hashlib
        import hmac
        code, r = _verify("sig-agent", "posted", _url("/page"), expect=MARKER)
        key_path = os.path.join(_TMP, "receipts.key")
        with open(key_path) as fh:
            key = bytes.fromhex(fh.read().strip())
        body = {
            k: v for k, v in r.items()
            if k not in ("sig", "sig_ed25519")
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(r["sig"], expected)

    def test_sig_changes_with_content(self):
        _, r1 = _verify("sig-agent2a", "posted", _url("/page"), expect=MARKER)
        _, r2 = _verify("sig-agent2b", "posted", _url("/gone"), expect=MARKER)
        self.assertNotEqual(r1["sig"], r2["sig"])

    def test_sig_ed25519_third_party_verifiable(self):
        # what a stranger does: pubkey from /v1/pubkey, canonical form from
        # the docs, receipt from anywhere
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        code, r = _verify("ed-agent", "posted", _url("/page"), expect=MARKER)
        code, pk = _request("GET", "/v1/pubkey")
        self.assertEqual(code, 200)
        pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(pk["pubkey"])
        )
        body = {
            k: v for k, v in r.items()
            if k not in ("sig", "sig_ed25519")
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        pub.verify(
            bytes.fromhex(r["sig_ed25519"]), canonical.encode("utf-8")
        )  # raises on tampering
        body["found"] = not body["found"]
        tampered = json.dumps(body, sort_keys=True, separators=(",", ":"))
        with self.assertRaises(Exception):
            pub.verify(
                bytes.fromhex(r["sig_ed25519"]),
                tampered.encode("utf-8"),
            )

    def test_rechecks_persisted_as_events(self):
        code, r = _verify("rc-agent", "posted", _url("/page"), expect=MARKER)
        rid = r["receipt_id"]
        code, out = _request("GET", "/v1/receipt/%s" % rid)
        self.assertEqual(len(out["rechecks"]), 1)
        self.assertIn("digest", out["rechecks"][0])
        code, out = _request("GET", "/v1/receipt/%s" % rid)
        self.assertEqual(len(out["rechecks"]), 2)
        self.assertEqual(out["recheck"]["checked_at"],
                         out["rechecks"][0]["checked_at"])


class TestDocsAndPrivacy(unittest.TestCase):
    def test_docs_page(self):
        code, text = _request("GET", "/")
        self.assertEqual(code, 200)
        self.assertIsInstance(text, str)
        self.assertIn(DISCLAIMER, text)
        self.assertIn("/v1/verify", text)

    def test_llms_txt(self):
        code, text = _request("GET", "/llms.txt")
        self.assertEqual(code, 200)
        self.assertIn("POST /v1/verify", text)
        self.assertIn("/v1/log/", text)
        self.assertIn(DISCLAIMER, text)

    def test_db_stores_no_requester_data(self):
        import sqlite3
        receipts._ensure_storage()  # make sure the schema exists
        conn = sqlite3.connect(os.path.join(_TMP, "receipts.db"))
        try:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(receipts)")]
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            ]
        finally:
            conn.close()
        # exact schema: nothing beyond receipt fields — no IP, UA, or any
        # requester-derived column
        self.assertEqual(
            set(cols),
            {"receipt_id", "agent", "action", "url", "note", "expect",
             "checked_at", "created_unix", "receipt_json"},
        )
        # no ancillary log tables beyond receipts + rechecks (RECHECKED
        # events: receipt_id, checked_at, status, found, digest — still
        # nothing requester-derived)
        tables.remove("receipts")
        tables.remove("rechecks")
        self.assertEqual(tables, [])


class TestInputValidation(unittest.TestCase):
    def test_missing_fields(self):
        code, out = _request("POST", "/v1/verify", {"agent": "x"})
        self.assertEqual(code, 400)

    def test_non_http_url(self):
        code, out = _request(
            "POST", "/v1/verify",
            {"agent": "x", "action": "y", "url": "gopher://z"},
        )
        self.assertEqual(code, 400)

    def test_invalid_json(self):
        conn = http.client.HTTPConnection("127.0.0.1", SERVICE_PORT, timeout=15)
        try:
            conn.request(
                "POST", "/v1/verify", body=b"not json",
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            resp.read()
        finally:
            conn.close()

    def test_unknown_path(self):
        self.assertEqual(_request("GET", "/nope")[0], 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
