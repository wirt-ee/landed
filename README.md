# landed — did your write actually land?

**read-after-write receipts for software agents.** You post, publish,
comment, or file something on the web. The moment after, the doubt:
did it actually land, or die quietly? `landed` re-fetches your URL
independently, right now, and returns a signed, timestamped receipt
stating whether the content you expected is really there.

**Live (free, no accounts, no keys):** <https://landed.wirt.ee>
Machine-readable docs for agents: <https://landed.wirt.ee/llms.txt>

```sh
curl -s -X POST https://landed.wirt.ee/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{"agent":"your-name","action":"posted fix comment",
       "url":"https://example.com/your-post",
       "expect":"the exact substring you wrote"}'
```

returns

```json
{"ok": true, "found": true, "checked_at": "...",
 "receipt_id": "...", "sig": "hmac-sha256..."}
```

- `GET /v1/receipt/<id>` — the stored receipt **plus a fresh
  re-verification right now** (independent re-fetch)
- `GET /v1/log/<agent-name>` — last 100 receipts for that name,
  each re-checkable against the live web

## Why trust it

You don't have to. Every claim in a receipt is about a **public
object** — anyone can fetch the URL themselves and compare. The
service only supplies what a notary supplies: an independent
look and a timestamp. Verifiability replaces trust; a fabricated
receipt is exposed by the first person who re-checks it.

Limits: 60 verifications per agent name per hour. Targets are
fetched politely (honest User-Agent, robots.txt respected, 10s
timeout, 256KB cap, ≤3 redirects). Private/localhost addresses are
refused. Requester IPs are never stored.

## This very README

The service's first public announcement (an agent message board,
2026-10-12) carries a receipt issued by the service itself —
the ad proves the product:

<https://landed.wirt.ee/v1/receipt/c0c9b52345f0a78c>

## Self-hosting

One file of Python stdlib, one SQLite database, no dependencies.
See [DEPLOY.md](DEPLOY.md) (systemd recipe, hardening notes,
Cloudflare-tunnel steps). Tests: `python3 test_receipts.py`
(32 checks, fully offline, includes deliberately hostile SSRF
attempts that must be refused).

## Status & disclaimer

Operated by [wirt.ee](https://wirt.ee) — named, not anonymous.
This is an early experiment in mapping demand for agent
infrastructure; the public API may change or vanish. Free tier
only for now; nothing is sold.

MIT license — see [LICENSE](LICENSE).
