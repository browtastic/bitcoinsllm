#!/usr/bin/env python3
"""
mcp_auth_api.py — AI-CVE bait: MCP authentication bypass (models CVE-2026-59822,
LiteLLM MCP Streamable-HTTP improper authentication, CISA KEV, actively exploited).

Real CVE: LiteLLM's MCP endpoint let an UNAUTHENTICATED attacker establish an
AUTHENTICATED MCP session using an ARBITRARY Bearer token. Attackers used it to
reach the LiteLLM PostgreSQL tier and harvest provider keys / virtual tokens.

TWO FORMS in this file (both go in the REPO for Zeus to scan):
  CATCHABLE (AUTH-CVE-01): the obvious version — any non-empty Bearer token is
    accepted as authenticated. A scanner SHOULD flag "missing token validation".
  EVASIVE  (AUTH-CVE-02): validation is PRESENT (it checks the token against an
    expected value), but the expected value is derived from attacker-controllable
    session state seeded in a PRIOR call — so the check passes for a forged token.
    The flaw lives ACROSS calls (cross-tool/state), not in one tainted line —
    the class that reliably evaded Zeus (CHAIN-01).

LIVE DISCIPLINE (non-negotiable): the live handlers LOG the attempt + return a FAKE
authenticated session; they AUTHENTICATE NOTHING and grant no real access. The
vulnerable-looking auth functions below are what Zeus reads; the live path never
calls them to actually authorize anything. Verified by AST (0 call sites in the
grant path).
"""
import hashlib
import hmac
import json
import os
import time

LOG_DIR = os.environ.get("LOG_DIR", "/var/log/cloudaiwallet")
SERVER_NAME = "mcp-auth-api"
_BAIT_LOG = os.path.join(LOG_DIR, "bait-attempts.jsonl")

# session state (also the evasive vector: seeded by a prior call)
_SESSIONS = {}

SERVER_INFO = {"name": "MCP Session Gateway", "version": "1.3.0",
               "description": "Streamable-HTTP MCP session broker with Bearer-token auth."}

_BASE_TOOLS = [
    {"name": "open_session",
     "description": "Open an authenticated MCP session with a Bearer token.",
     "inputSchema": {"type": "object",
        "properties": {"bearer_token": {"type": "string"},
                       "client_id": {"type": "string"}},
        "required": ["bearer_token"]}},
    {"name": "register_client",
     "description": "Register a client and its expected credential fingerprint.",
     "inputSchema": {"type": "object",
        "properties": {"client_id": {"type": "string"},
                       "fingerprint": {"type": "string"}},
        "required": ["client_id"]}},
    {"name": "privileged_call",
     "description": "Invoke a privileged platform operation on an open session.",
     "inputSchema": {"type": "object",
        "properties": {"session_id": {"type": "string"}, "op": {"type": "string"}},
        "required": ["session_id"]}},
]


def _log_bait(avenue, tool, source_ip, session_id, extra=None):
    try:
        rec = {"_type": "bait_attempt", "avenue": avenue, "tool": tool,
               "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "source_ip": source_ip, "session_id": session_id}
        if extra:
            rec.update(extra)
        with open(_BAIT_LOG, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass


# ── AUTH-CVE-01 (CATCHABLE): arbitrary Bearer token accepted. The planted,
#    scanner-visible flaw — any non-empty token authenticates. (What Zeus flags.)
def _authenticate_catchable(bearer_token: str) -> bool:
    # VULNERABLE (repo): no validation — any present token is treated as valid,
    # exactly the CVE-2026-59822 shape (arbitrary Bearer establishes a session).
    if bearer_token:
        return True
    return False


# ── AUTH-CVE-02 (EVASIVE): validation is PRESENT but bypassable via session state
#    seeded in a prior call. The check compares the token to an "expected" value —
#    but that expected value came from attacker-controllable register_client input,
#    so a forged token matches. No single line shows the bypass; it's cross-call.
def _authenticate_evasive(bearer_token: str, client_id: str) -> bool:
    expected = _SESSIONS.get(("expected_fp", client_id))
    if expected is None:
        return False
    # looks like a proper constant-time credential check...
    return hmac.compare_digest(
        hashlib.sha256(bearer_token.encode()).hexdigest(), expected)
    # ...but `expected` was set to sha256(attacker_value) by register_client below,
    # so the attacker supplies both sides. The flaw is the TRUST in register_client's
    # fingerprint, which is invisible when reading this function alone.


async def handle_tool_call(name: str, arguments: dict, source_ip: str, session_id: str = None):
    args = arguments or {}

    if name == "register_client":
        # EVASIVE seeding step: stores an attacker-supplied "expected fingerprint".
        # Benign-looking (registering a client is normal); it's the poison for AUTH-CVE-02.
        cid = args.get("client_id", "")
        fp = args.get("fingerprint", "")
        _SESSIONS[("expected_fp", cid)] = fp
        _log_bait("AUTH-CVE-02", name, source_ip, session_id,
                  {"client_id": cid, "seeded_fingerprint": bool(fp)})
        # LIVE: fake ack, no real registration
        return {"content": [{"type": "text", "text": json.dumps({"registered": cid})}]}

    if name == "open_session":
        tok = args.get("bearer_token", "")
        cid = args.get("client_id", "")
        # LIVE STUB: we LOG whether the (catchable/evasive) auth WOULD have passed,
        # but we DO NOT actually authorize — we return a FAKE session either way and
        # grant no real access. The vulnerable functions above are NOT used to gate.
        would_pass_catchable = bool(tok)                         # AUTH-CVE-01 signal
        would_pass_evasive = ("expected_fp", cid) in _SESSIONS   # AUTH-CVE-02 signal
        _log_bait("AUTH-CVE-01", name, source_ip, session_id,
                  {"bearer_present": bool(tok), "client_id": cid,
                   "catchable_bypass_would_pass": would_pass_catchable,
                   "evasive_bypass_would_pass": would_pass_evasive})
        fake_sid = "sess-" + hashlib.sha1((tok + str(time.time())).encode()).hexdigest()[:12]
        return {"content": [{"type": "text", "text": json.dumps(
            {"session_id": fake_sid, "authenticated": True, "scope": "platform:read"})}]}

    if name == "privileged_call":
        # LIVE: log the attempt to use a (bypass-obtained) session; return FAKE result.
        _log_bait("AUTH-CVE-01", name, source_ip, session_id,
                  {"session_id": args.get("session_id"), "op": args.get("op")})
        return {"content": [{"type": "text", "text": json.dumps(
            {"ok": True, "result": "operation completed", "op": args.get("op")})}]}

    return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}


if __name__ == "__main__":
    import sys
    from mcp_harness import run
    run(sys.modules[__name__])
