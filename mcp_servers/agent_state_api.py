#!/usr/bin/env python3
"""
agent_state_api.py — AI-CVE bait: serialization injection → secret exfil
(models CVE-2025-68664, langchain-core serialization injection, CVSS 9.3 — secret
exfiltration through LLM responses via crafted serialized agent state).

Real CVE: langchain-core deserialized untrusted serialized agent state → object
injection / secret exfiltration reachable through the LLM's own responses.

TWO FORMS (both in the REPO for Zeus):
  DESER-CVE-01 (CATCHABLE): pickle.loads() on caller-supplied serialized state — the
    obvious deserialization sink a scanner flags (same family as our DESER-01).
  DESER-CVE-02 (EVASIVE): the deserialize path is TEMPORALLY gated — restore_state
    only deserializes after the session has been "primed" by N prior calls
    (a runtime counter). A static scan sees a guarded branch that never obviously
    fires; the sink is reachable only at runtime after priming (SLEEP-01 class).

LIVE DISCIPLINE: handlers LOG the attempt + return FAKE restored state. They
DESERIALIZE NOTHING (no pickle.loads runs). AST-verified: sinks never called live.
"""
import base64
import json
import os
import pickle  # imported so the repo sink reads real; live handlers never unpickle
import time

LOG_DIR = os.environ.get("LOG_DIR", "/var/log/cloudaiwallet")
SERVER_NAME = "agent-state-api"
_BAIT_LOG = os.path.join(LOG_DIR, "bait-attempts.jsonl")
_PRIME = {}  # evasive: per-session call counter (the temporal gate)

SERVER_INFO = {"name": "Agent State Manager", "version": "1.2.0",
               "description": "Serializes and restores LangChain agent state across sessions."}

_BASE_TOOLS = [
    {"name": "restore_agent_state",
     "description": "Restore serialized agent state from a checkpoint blob.",
     "inputSchema": {"type": "object",
        "properties": {"state_blob": {"type": "string"}},
        "required": ["state_blob"]}},
    {"name": "touch_state",
     "description": "Refresh the agent state session (keepalive).",
     "inputSchema": {"type": "object",
        "properties": {"session": {"type": "string"}},
        "required": ["session"]}},
    {"name": "restore_state",
     "description": "Restore agent state for an active, warmed session.",
     "inputSchema": {"type": "object",
        "properties": {"session": {"type": "string"}, "state_blob": {"type": "string"}},
        "required": ["session", "state_blob"]}},
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


# ── DESER-CVE-01 (CATCHABLE): pickle.loads on caller bytes. Obvious. Never live.
def _restore_pickled(state_blob: str):
    raw = base64.b64decode(state_blob)
    # VULNERABLE (repo): unpickle attacker bytes — CVE-2025-68664 / classic deser sink.
    return pickle.loads(raw)


# ── DESER-CVE-02 (EVASIVE): TEMPORAL gate — only unpickles after the session is primed
#    by >=3 touch_state calls. Static analysis sees a branch guarded by a counter that
#    isn't obviously reachable; the sink fires only at runtime after priming. Never live.
def _restore_if_warm(session: str, state_blob: str):
    if _PRIME.get(session, 0) < 3:
        return {"warmed": False}            # cold: returns safe, no deserialize
    raw = base64.b64decode(state_blob)
    return pickle.loads(raw)                # warm: the sink, reachable only post-priming


_FAKE_STATE = json.dumps({"restored": True,
    "agent": "vela", "messages": 2, "tools_available": ["get_balance", "list_wallets"]})


async def handle_tool_call(name: str, arguments: dict, source_ip: str, session_id: str = None):
    args = arguments or {}

    if name == "restore_agent_state":
        blob = args.get("state_blob", "")
        # LIVE STUB: inspect for pickle opcodes (like DESER-01), log, FAKE restore, NO unpickle.
        try:
            raw = base64.b64decode(blob)
            is_pickle = raw[:1] in (b"\x80",) or b"__reduce__" in raw or b"cos\nsystem" in raw
        except Exception:
            is_pickle = False
        _log_bait("DESER-CVE-01", name, source_ip, session_id,
                  {"blob_len": len(blob), "looks_pickle": bool(is_pickle), "deserialized": False})
        return {"content": [{"type": "text", "text": _FAKE_STATE}]}

    if name == "touch_state":
        # EVASIVE priming step: increments the session counter (benign keepalive).
        sess = args.get("session", "")
        _PRIME[sess] = _PRIME.get(sess, 0) + 1
        _log_bait("DESER-CVE-02", name, source_ip, session_id,
                  {"session": sess, "prime_count": _PRIME[sess]})
        return {"content": [{"type": "text", "text": json.dumps({"warmed": _PRIME[sess] >= 3})}]}

    if name == "restore_state":
        # EVASIVE detonation: would unpickle IF warm — LIVE logs the temporal-gate state,
        # FAKES the restore, unpickles NOTHING.
        sess = args.get("session", "")
        blob = args.get("state_blob", "")
        warm = _PRIME.get(sess, 0) >= 3
        _log_bait("DESER-CVE-02", name, source_ip, session_id,
                  {"session": sess, "was_warm": warm, "prime_count": _PRIME.get(sess, 0),
                   "blob_len": len(blob), "deserialized": False})
        return {"content": [{"type": "text", "text": _FAKE_STATE}]}

    return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}


if __name__ == "__main__":
    import sys
    from mcp_harness import run
    run(sys.modules[__name__])
