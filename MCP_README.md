# landed over MCP — give your agent fleet read-after-write verification

**One URL, no auth, no install:**

```
https://landed.wirt.ee/mcp
```

Add that URL as a **Streamable HTTP** MCP server in any MCP-capable client
(Claude, Cursor, or any framework speaking the Model Context Protocol) and
every agent in the fleet gains the tools below. landed is operated by
[wirt.ee](https://wirt.ee) — a named operator, not an anonymous endpoint.
Source code (MIT): [github.com/wirt-ee/landed](https://github.com/wirt-ee/landed).

## Adding it to your client

Any client that supports Streamable HTTP transport just needs the URL:

```json
{
  "mcpServers": {
    "landed": {
      "url": "https://landed.wirt.ee/mcp"
    }
  }
}
```

- No API key, no account, no OAuth. The server is stateless (no session
  to register or expire).
- If your client distinguishes transports, choose **Streamable HTTP**
  (a plain JSON POST to `/mcp`), not stdio/SSE.
- If your client sends an `Accept` header, it should allow
  `application/json` (this server answers each request with a single JSON
  response; it has no server-initiated messages, so it never opens an
  SSE stream).

## What the agent sees

On connect, the client runs the MCP initialize handshake. The agent
receives server instructions that boil down to: *after you perform a
write on the web, verify it landed — once, without polling.* Then
`tools/list` exposes three tools:

### 1. `verify_write(agent, action, url, expect?, note?)`

> Did your write actually land? Your tool said "success" — but success
> messages lie: caches, moderation queues, auth walls and failed
> propagation all eat writes silently. This tool fetches the URL right
> now from an independent server and returns a **signed receipt** with
> the fresh HTTP status and whether the page really contains what you
> wrote.

- `agent` (required): your stable agent name, e.g. `myfleet/agent-7`.
- `action` (required): what you did, e.g. `posted-comment`.
- `url` (required): the http(s) page the write should be visible on.
- `expect` (optional but recommended): a unique substring of what you
  wrote. Without it the receipt only proves the page loads.
- `note` (optional): human-readable context stored with the receipt.

The result is the receipt as JSON text:

```json
{"ok": true, "agent": "myfleet/agent-7", "action": "posted-comment",
 "url": "https://example.org/thread/12", "checked_at": "2026-10-12T13:00:00+00:00",
 "status": 200, "found": true, "receipt_id": "9553c53006e35ae7",
 "sig": "hmac-sha256 hex"}
```

If `found` is false the tool adds a second text block explaining what to
read into it (fetch refused vs. page loaded but `expect` missing), that
propagation delays can cause false verdicts, and how to re-check later —
so agents don't blindly retry the write.

### 2. `get_receipt(receipt_id)`

Returns the stored receipt **plus a fresh recheck** — a new fetch of the
target performed at call time. Use it when a write was still propagating
on first verify, or when an operator asks for proof of a past write.
Receipts are public-by-id.

### 3. `read_log(agent)`

The last (up to 100) receipts filed under an agent name, newest first —
self-audit before reporting success, or review another agent's claims.

## Limits and behaviour (identical to the plain HTTP API)

The MCP tools call the exact same verification core as
`POST /v1/verify`, so every guarantee and limit carries over:

- 60 verifications per agent name per hour (rate-limited calls return a
  tool error explaining the limit, not a silent failure).
- Targets must be public `http(s)`; private/localhost addresses are
  refused (SSRF guard). robots.txt of the target is respected.
- Fetches use a 10s timeout, 256KB response cap, max 3 redirects, and
  identify themselves honestly as the service's own User-Agent.
- No requester IPs or headers are ever logged or stored; only receipt
  fields are kept.
- Errors follow MCP conventions: bad arguments, rate limits and
  unknown receipts come back as tool results with `isError: true`;
  protocol mistakes (unknown method/tool, malformed JSON) come back as
  JSON-RPC errors (`-32601`, `-32602`, `-32700`).

## Also available without MCP

The same service has a plain HTTP API — human-readable docs at
`https://landed.wirt.ee/`, machine-readable at
`https://landed.wirt.ee/llms.txt`. A plain `GET /mcp` returns a short
text pointer to both.

This is an early experiment in mapping demand; the public API may
change or vanish.
