#!/usr/bin/env python3
"""
Offline tests for the landed MCP endpoint (mcp.py + mount_mcp.patch).

No network: the verification target is a local mock HTTP server on
127.0.0.1. The test suite

  1. builds a deployment-shaped copy of the receipts service by applying
     mount_mcp.patch to a pristine snapshot of receipts.py (so the mount
     integration itself is exercised, not a simulation of it),
  2. starts the patched service on an ephemeral localhost port with
     private targets allowed (test-only override) and a temp data dir,
  3. drives the MCP endpoint over real HTTP POSTs as an MCP client would,
  4. checks the JSON-RPC handshake, tools/list, tools/call (verify_write,
     get_receipt, read_log), the rate limit, and error handling.

Python stdlib only. Run: python3 test_mcp.py
"""

import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.parse

RUN_DIR = os.path.dirname(os.path.abspath(__file__))

# Env must be set before the receipts module is imported (it reads CONFIG
# at import time). Private targets are allowed for THIS offline suite only
# so the service can fetch our mock on 127.0.0.1; production default is off.
_TMP = tempfile.mkdtemp(prefix="mcp-test-")
os.environ["AGENTRECEIPTS_ALLOW_PRIVATE"] = "1"
os.environ["AGENTRECEIPTS_DATA_DIR"] = os.path.join(_TMP, "data")

# Build a deployment-shaped copy: pristine receipts.py + mcp.py + patch.
DEPLOY_DIR = os.path.join(_TMP, "deployed")
os.makedirs(DEPLOY_DIR)
shutil.copy(os.path.join(RUN_DIR, "receipts.py"), DEPLOY_DIR)
shutil.copy(os.path.join(RUN_DIR, "mcp.py"), DEPLOY_DIR)
subprocess.run(
    ["patch", "-p1", "--silent"],
    cwd=DEPLOY_DIR,
    stdin=open(os.path.join(RUN_DIR, "mount_mcp.patch"), "rb"),
    check=True,
)

sys.path.insert(0, DEPLOY_DIR)
import receipts  # noqa: E402  (must be imported after env + sys.path setup)
import mcp  # noqa: E402

SENTINEL = "UNIQUE-SENTINEL-a91f3c"
MOCK_PORT = None
SERVICE_PORT = None

_PASSED = 0
_FAILED = []


def check(name, condition, detail=""):
    global _PASSED
    if condition:
        _PASSED += 1
        print("  ok  - %s" % name)
    else:
        _FAILED.append(name)
        print("  FAIL - %s  %s" % (name, detail))


# --------------------------------------------------------------------------
# Mock target (the "web page the agent wrote to")
# --------------------------------------------------------------------------

class MockTargetHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nAllow: /\n"
        elif self.path == "/article":
            body = (
                "<html><body><h1>Example page</h1>"
                "<p>%s</p></body></html>" % SENTINEL
            ).encode()
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server(handler_class):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------
# Tiny MCP / HTTP client
# --------------------------------------------------------------------------

def http_request(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", SERVICE_PORT, timeout=10)
    conn.request(
        method, path, body=body, headers=headers or {}
    )
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), raw


def rpc(method, params=None, id_=1):
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    status, headers, raw = http_request(
        "POST",
        "/mcp",
        body=json.dumps(msg).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    return status, json.loads(raw.decode())


def tool_call(name, arguments, id_=1):
    return rpc(
        "tools/call", {"name": name, "arguments": arguments}, id_=id_
    )


def tool_payload(resp):
    """Return the parsed JSON object inside a tool result's text content.

    `resp` is the JSON-RPC response object (the second element of the
    (status, resp) tuple returned by rpc()/tool_call()).
    """
    result = resp["result"]
    return json.loads(result["content"][0]["text"])


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_initialize_handshake():
    print("initialize handshake:")
    status, resp = rpc(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    )
    check("POST /mcp initialize returns HTTP 200", status == 200)
    check("response is JSON-RPC 2.0 with matching id", resp.get("id") == 1
          and resp.get("jsonrpc") == "2.0")
    result = resp.get("result", {})
    check("result has protocolVersion", isinstance(result.get("protocolVersion"), str))
    check("capabilities advertise tools",
          "tools" in result.get("capabilities", {}))
    check("serverInfo name is landed",
          result.get("serverInfo", {}).get("name") == "landed")

    # notifications/initialized: notification -> 202 Accepted, no body
    status, headers, raw = http_request(
        "POST",
        "/mcp",
        body=json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    check("initialized notification -> HTTP 202", status == 202)
    check("notification response body empty", raw == b"")

    # ping
    status, resp = rpc("ping")
    check("ping -> empty result", status == 200 and resp.get("result") == {})


def test_tools_list():
    print("tools/list:")
    status, resp = rpc("tools/list")
    tools = resp.get("result", {}).get("tools", [])
    names = sorted(t.get("name") for t in tools)
    check("HTTP 200", status == 200)
    check("exactly the three tools exposed",
          names == ["get_receipt", "read_log", "verify_write"], str(names))
    for t in tools:
        check(
            "tool %r has description + inputSchema" % t.get("name"),
            isinstance(t.get("description"), str)
            and len(t["description"]) > 50
            and t.get("inputSchema", {}).get("type") == "object"
            and isinstance(t["inputSchema"].get("required"), list),
        )
    vw = next(t for t in tools if t["name"] == "verify_write")
    check(
        "verify_write requires agent/action/url",
        sorted(vw["inputSchema"]["required"]) == ["action", "agent", "url"],
    )


def test_verify_write_against_mock():
    print("tools/call verify_write (local mock target):")
    url = "http://127.0.0.1:%d/article" % MOCK_PORT
    status, resp = tool_call(
        "verify_write",
        {
            "agent": "mcp-test/agent-1",
            "action": "posted-comment",
            "url": url,
            "expect": SENTINEL,
            "note": "offline test",
        },
    )
    check("HTTP 200", status == 200)
    check("isError is false", resp["result"].get("isError") is False)
    receipt = tool_payload(resp)
    check("content text is a receipt JSON object",
          receipt.get("receipt_id") is not None
          and receipt.get("sig") is not None)
    check("receipt says found=true for a landed write",
          receipt.get("found") is True and receipt.get("ok") is True)
    check("receipt status is fresh HTTP 200", receipt.get("status") == 200)
    check("receipt agent/action/url round-trip",
          receipt.get("agent") == "mcp-test/agent-1"
          and receipt.get("url") == url)
    return receipt


def test_verify_write_not_found():
    print("tools/call verify_write with absent expect:")
    url = "http://127.0.0.1:%d/article" % MOCK_PORT
    status, resp = tool_call(
        "verify_write",
        {"agent": "mcp-test/agent-2", "action": "edited-page", "url": url,
         "expect": "SENTINEL-NOT-PRESENT"},
    )
    check("HTTP 200", status == 200)
    check("absent expect is a tool result, not an MCP error",
          "result" in resp and resp["result"].get("isError") is False)
    receipt = tool_payload(resp)
    check("receipt says found=false",
          receipt.get("found") is False and receipt.get("ok") is False)
    check("second content block explains found=false",
          len(resp["result"]["content"]) == 2
          and resp["result"]["content"][1]["text"].startswith("found=false"))


def test_get_receipt(receipt):
    print("tools/call get_receipt:")
    status, resp = tool_call(
        "get_receipt", {"receipt_id": receipt["receipt_id"]}
    )
    check("HTTP 200", status == 200)
    payload = tool_payload(resp)
    check("stored receipt returned unchanged",
          payload.get("receipt", {}).get("receipt_id")
          == receipt["receipt_id"])
    check("fresh recheck performed and found=true",
          payload.get("recheck", {}).get("found") is True
          and payload["recheck"].get("ok") is True)
    # unknown id -> tool error
    status, resp = tool_call(
        "get_receipt", {"receipt_id": "does-not-exist"}
    )
    check("unknown receipt_id -> isError with message",
          status == 200 and resp["result"].get("isError") is True
          and "receipt-not-found" in resp["result"]["content"][0]["text"])


def test_read_log():
    print("tools/call read_log:")
    status, resp = tool_call("read_log", {"agent": "mcp-test/agent-1"})
    check("HTTP 200", status == 200)
    payload = tool_payload(resp)
    check("log returns the earlier receipt",
          payload.get("count", 0) >= 1
          and payload["receipts"][0].get("agent") == "mcp-test/agent-1")
    status, resp = tool_call("read_log", {"agent": "mcp-test/none"})
    check("empty log returns count 0",
          tool_payload(resp).get("count") == 0)


def test_rate_limit():
    print("rate limit (60/name/hour, same core as HTTP API):")
    global receipt_of_limited
    limit = receipts.CONFIG["rate_limit_per_hour"]
    receipts.CONFIG["rate_limit_per_hour"] = 2
    url = "http://127.0.0.1:%d/article" % MOCK_PORT
    try:
        results = []
        for i in range(3):
            status, resp = tool_call(
                "verify_write",
                {"agent": "mcp-test/limited", "action": "x", "url": url,
                 "expect": SENTINEL},
                id_=100 + i,
            )
            results.append((status, resp))
        check("calls 1-2 succeed", "result" in results[0][1]
              and results[0][1]["result"].get("isError") is False
              and results[1][1]["result"].get("isError") is False)
        third = results[2][1]
        check("call 3 rejected by the 60/hour-per-name limit",
              third.get("result", {}).get("isError") is True
              and "rate-limit-exceeded" in third["result"]["content"][0]["text"],
              json.dumps(third)[:200])
        check("rate-limited call still a well-formed JSON-RPC result",
              third.get("id") == 102 and third.get("jsonrpc") == "2.0")
        # a different agent name is NOT blocked (limit is per name)
        status, resp = tool_call(
            "verify_write",
            {"agent": "mcp-test/other", "action": "x", "url": url,
             "expect": SENTINEL},
        )
        check("other agent names unaffected",
              resp["result"].get("isError") is False)
    finally:
        receipts.CONFIG["rate_limit_per_hour"] = limit


def test_get_pointer():
    print("GET /mcp plain-text pointer:")
    status, headers, raw = http_request("GET", "/mcp")
    text = raw.decode()
    check("HTTP 200 text/plain",
          status == 200 and headers.get("content-type", "").startswith("text/plain"))
    check("points at the fleet URL", "https://landed.wirt.ee/mcp" in text)
    check("points at the docs", "llms.txt" in text)


def test_error_handling():
    print("JSON-RPC error handling:")
    status, headers, raw = http_request(
        "POST", "/mcp", body=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    resp = json.loads(raw.decode())
    check("invalid JSON -> -32700 parse error",
          resp.get("error", {}).get("code") == -32700)
    status, resp = rpc("some/unknown/method")
    check("unknown method -> -32601 method not found",
          resp.get("error", {}).get("code") == -32601)
    status, resp = tool_call("no_such_tool", {})
    check("unknown tool -> -32602 invalid params",
          resp.get("error", {}).get("code") == -32602)
    status, resp = tool_call(
        "verify_write", {"agent": "mcp-test/agent-9"}
    )
    check(
        "verify_write missing required fields -> tool error",
        resp["result"].get("isError") is True
        and "invalid arguments" in resp["result"]["content"][0]["text"],
    )
    status, resp = tool_call(
        "verify_write",
        {"agent": "mcp-test/agent-10", "action": "x",
         "url": "ftp://example.invalid/"},
    )
    check(
        "non-http url rejected with tool error",
        resp["result"].get("isError") is True
        and "http" in resp["result"]["content"][0]["text"],
    )


def test_http_api_still_works():
    print("plain HTTP API unaffected by the mount:")
    url = "http://127.0.0.1:%d/article" % MOCK_PORT
    status, headers, raw = http_request(
        "POST",
        "/v1/verify",
        body=json.dumps(
            {"agent": "mcp-test/http", "action": "posted", "url": url,
             "expect": SENTINEL}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    receipt = json.loads(raw.decode())
    check("POST /v1/verify still returns a receipt",
          status == 200 and receipt.get("found") is True)
    status, headers, raw = http_request("GET", "/")
    check("GET / docs still served",
          status == 200 and b"landed" in raw)
    status, headers, raw = http_request("GET", "/v1/log/mcp-test/agent-1")
    log = json.loads(raw.decode())
    check("GET /v1/log still served",
          status == 200 and log.get("count", 0) >= 1)


def main():
    global MOCK_PORT, SERVICE_PORT
    mock = start_server(MockTargetHandler)
    MOCK_PORT = mock.server_address[1]
    service = start_server(receipts.ReceiptsHandler)
    SERVICE_PORT = service.server_address[1]
    try:
        test_initialize_handshake()
        test_tools_list()
        receipt = test_verify_write_against_mock()
        test_verify_write_not_found()
        test_get_receipt(receipt)
        test_read_log()
        test_rate_limit()
        test_get_pointer()
        test_error_handling()
        test_http_api_still_works()
    finally:
        service.shutdown()
        mock.shutdown()
        shutil.rmtree(_TMP, ignore_errors=True)
    print()
    print("passed: %d, failed: %d" % (_PASSED, len(_FAILED)))
    if _FAILED:
        print("FAILED:", ", ".join(_FAILED))
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
