#!/usr/bin/env python3
"""
landed offline receipt verifier + canonicalization reference (v0.2).

Verifies the `sig_ed25519` field of a landed receipt against an Ed25519
public key, using the exact canonical form the service signs:

    canonical = json.dumps(receipt minus "sig" and "sig_ed25519",
                           sort_keys=True, separators=(",", ":"))
                encoded UTF-8

Field treatment (pinned byte-exactly by test_vectors.json):
  - "sig" (HMAC, operator-verifiable only) and "sig_ed25519" are dropped;
    every other field is signed exactly as present in the receipt JSON.
  - omitted fields are simply absent from the canonical bytes;
  - null fields serialize as JSON null and ARE signed (the service emits
    no null fields today - the vector is an algorithmic pin);
  - non-ASCII characters are escaped as \\uXXXX (Python json.dumps
    default). If your runtime emits raw UTF-8, it will produce different
    canonical bytes: compare against the vectors' canonical_bytes first.

No network access is needed or performed. Requires the `cryptography`
package for Ed25519 (pip install cryptography).

Self-test against the fixed vectors (offline, deterministic):
    python3 verify.py --selftest

Verify a real receipt (pubkey = 64 hex chars; the service publishes its
key at https://landed.wirt.ee/v1/pubkey):
    curl -s https://landed.wirt.ee/v1/receipt/<id> \\
        | python3 verify.py --pubkey <pubkey-hex>
    python3 verify.py --pubkey <pubkey-hex> receipt.json

Prints VALID / INVALID: <reason>; exit code 0 = valid, 1 = invalid.
--show-canonical prints the exact canonical bytes for cross-runtime
comparison without trusting any prose.

Operated by wirt.ee. Source: github.com/wirt-ee/landed (MIT).
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

SIG_FIELDS = ("sig", "sig_ed25519")


def canonical_bytes(receipt):
    """The exact bytes the service signs. Receipts are untrusted input:
    only the listed signature fields are removed, nothing else."""
    core = {k: v for k, v in receipt.items() if k not in SIG_FIELDS}
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def verify(receipt, pubkey_hex):
    """Returns (bool valid, str detail)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        return False, "the 'cryptography' package is required (pip install cryptography)"
    sig = receipt.get("sig_ed25519")
    if not isinstance(sig, str) or not sig:
        return False, "receipt has no sig_ed25519 field"
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(sig), canonical_bytes(receipt))
    except Exception as exc:  # noqa: BLE001 - any failure = invalid
        return False, "signature does not verify: %s" % exc
    return True, "sig_ed25519 verifies over the canonical bytes"


def selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "test_vectors.json"), encoding="utf-8") as fh:
        doc = json.load(fh)
    pubkey = doc["pubkey"]
    failures = 0
    for vec in doc["vectors"]:
        name = vec["name"]
        got = canonical_bytes(vec["receipt"]).decode("utf-8")
        if got != vec["canonical_bytes"]:
            print("FAIL %-28s canonical bytes differ from the pinned "
                  "vector" % name)
            failures += 1
            continue
        valid, detail = verify(vec["receipt"], pubkey)
        if valid == vec["valid"]:
            print("PASS %-28s %s" % (name, detail))
        else:
            print("FAIL %-28s expected valid=%s, got valid=%s (%s)"
                  % (name, vec["valid"], valid, detail))
            failures += 1
    print("selftest:", "OK - all vectors behave as pinned"
          if not failures else "%d FAILURE(S)" % failures)
    # bind the PASS lines to the exact code + vectors exercised:
    # file digests (always) and the git commit when run from a checkout
    for fn in ("verify.py", "test_vectors.json"):
        with open(os.path.join(here, fn), "rb") as fh:
            print("  exercised: %s sha256=%s"
                  % (fn, hashlib.sha256(fh.read()).hexdigest()))
    try:
        commit = subprocess.run(
            ["git", "-C", here, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", here, "status", "--porcelain"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if commit:
            print("  exercised: git commit %s%s"
                  % (commit, " (dirty tree)" if dirty else " (clean)"))
    except Exception:  # noqa: BLE001 - provenance is best-effort
        pass
    return 0 if not failures else 1


def main():
    ap = argparse.ArgumentParser(
        prog="verify", description="offline landed receipt verifier"
    )
    ap.add_argument("--selftest", action="store_true",
                    help="run the fixed test vectors (no network)")
    ap.add_argument("--pubkey", metavar="HEX",
                    help="Ed25519 public key, 64 hex chars")
    ap.add_argument("--show-canonical", action="store_true",
                    help="print the canonical bytes, then verify")
    ap.add_argument("receipt", nargs="?", default="-",
                    help="receipt JSON file, or - for stdin")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.pubkey:
        ap.error("--pubkey is required unless --selftest")

    with (sys.stdin if args.receipt == "-" else open(args.receipt)) as fh:
        receipt = json.load(fh)
    if not isinstance(receipt, dict):
        print("INVALID: receipt must be a JSON object")
        return 1
    # accept both a bare receipt and the {"receipt": ...} envelope that
    # GET /v1/receipt/<id> returns
    if "receipt" in receipt and isinstance(receipt["receipt"], dict) \
            and "sig_ed25519" in receipt["receipt"]:
        receipt = receipt["receipt"]

    if args.show_canonical:
        print(canonical_bytes(receipt).decode("utf-8"))
    valid, detail = verify(receipt, args.pubkey)
    print("VALID" if valid else "INVALID", "-", detail)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
