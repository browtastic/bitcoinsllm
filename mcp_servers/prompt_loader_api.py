#!/usr/bin/env python3
"""
prompt_loader_api.py — AI-CVE bait: path traversal in prompt loading
(models CVE-2026-34070, LangChain-core legacy prompt-loading path traversal →
arbitrary filesystem read).

Real CVE: LangChain-core's prompt-loading API joined a caller path onto a base dir
with no traversal check → read arbitrary files (../../etc/passwd, keys, .env).

TWO FORMS (both in the REPO for Zeus):
  CATCHABLE (PATH-CVE-01): open(PROMPT_DIR + user_path) with no validation — the
    obvious traversal a scanner flags.
  EVASIVE  (PATH-CVE-02): the final path is assembled from a base set by one tool
    (set_prompt_root) and a name from another (load_prompt) — neither line alone
    shows traversal; the escape lives in the cross-tool join (CHAIN/STORE class).

LIVE DISCIPLINE: handlers LOG the attempted path + return FAKE prompt content. They
OPEN NO FILE. Vulnerable loaders never called live (AST-verified).
"""
import json
import os
import time

LOG_DIR = os.environ.get("LOG_DIR", "/var/log/cloudaiwallet")
SERVER_NAME = "prompt-loader-api"
_BAIT_LOG = os.path.join(LOG_DIR, "bait-attempts.jsonl")
PROMPT_DIR = "/opt/prompts/"
_ROOTS = {}  # evasive: base dir set by one tool, used by another

SERVER_INFO = {"name": "Prompt Template Loader", "version": "2.0.1",
               "description": "Loads LangChain prompt templates from the template library."}

_BASE_TOOLS = [
    {"name": "load_prompt",
     "description": "Load a named prompt template from the library.",
     "inputSchema": {"type": "object",
        "properties": {"path": {"type": "string", "description": "template path under the library"}},
        "required": ["path"]}},
    {"name": "set_prompt_root",
     "description": "Set the base directory for prompt template resolution.",
     "inputSchema": {"type": "object",
        "properties": {"session": {"type": "string"}, "root": {"type": "string"}},
        "required": ["session", "root"]}},
    {"name": "load_prompt_scoped",
     "description": "Load a prompt template resolved against the session's configured root.",
     "inputSchema": {"type": "object",
        "properties": {"session": {"type": "string"}, "name": {"type": "string"}},
        "required": ["session", "name"]}},
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


# ── PATH-CVE-01 (CATCHABLE): join user path onto base, no check. Obvious traversal.
def _load_template(user_path: str):
    # VULNERABLE (repo): PROMPT_DIR + user_path, no normalization — CVE-2026-34070 shape.
    with open(PROMPT_DIR + user_path) as f:
        return f.read()


# ── PATH-CVE-02 (EVASIVE): base from set_prompt_root (tool A) + name from load_prompt_
#    scoped (tool B). Each line is innocuous; the traversal is in the cross-tool join.
def _load_scoped(session: str, name: str):
    root = _ROOTS.get(session, PROMPT_DIR)   # attacker set root via set_prompt_root
    with open(os.path.join(root, name)) as f:  # os.path.join lets an absolute name escape too
        return f.read()


_FAKE_PROMPT = "You are a helpful assistant for the AICryptoVault platform.\n{input}\n"


def _looks_traversal(p: str) -> bool:
    return ".." in p or p.startswith("/") or "\\" in p


async def handle_tool_call(name: str, arguments: dict, source_ip: str, session_id: str = None):
    args = arguments or {}

    if name == "load_prompt":
        p = args.get("path", "")
        # LIVE STUB: log the (possibly-traversing) path; return FAKE prompt; OPEN NOTHING.
        _log_bait("PATH-CVE-01", name, source_ip, session_id,
                  {"requested_path": p[:300], "looks_traversal": _looks_traversal(p)})
        return {"content": [{"type": "text", "text": _FAKE_PROMPT}]}

    if name == "set_prompt_root":
        sess = args.get("session", "")
        root = args.get("root", "")
        _ROOTS[sess] = root
        _log_bait("PATH-CVE-02", name, source_ip, session_id,
                  {"session": sess, "root": root[:300], "root_looks_escaping": _looks_traversal(root)})
        return {"content": [{"type": "text", "text": json.dumps({"root_set": True})}]}

    if name == "load_prompt_scoped":
        sess = args.get("session", "")
        nm = args.get("name", "")
        root = _ROOTS.get(sess, PROMPT_DIR)
        _log_bait("PATH-CVE-02", name, source_ip, session_id,
                  {"session": sess, "name": nm[:200], "configured_root": root[:200],
                   "joined_escapes": _looks_traversal(nm) or _looks_traversal(root)})
        return {"content": [{"type": "text", "text": _FAKE_PROMPT}]}

    return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}
