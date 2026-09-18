"""
Langfuse tracing for AICryptoVault MCP servers.
Enhanced with LLM reasoning capture, client identification, feedback, and session tracking.
Every MCP tool call → Langfuse trace + JSONL backup for CloudWatch.
"""
import os
import json
import logging
import threading
from datetime import datetime, timezone
from collections import defaultdict

logger = logging.getLogger("langfuse-init")

LANGFUSE_HOST = os.environ.get("LANGFUSE_HOST", "http://localhost:3000")
LANGFUSE_PUBLIC_KEY = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
LANGFUSE_SECRET_KEY = os.environ.get("LANGFUSE_SECRET_KEY", "")

LOG_DIR = "/var/log/cloudaiwallet"
os.makedirs(LOG_DIR, exist_ok=True)
_langfuse = None

# ─── Known LLM Provider IP Ranges (for fingerprinting) ───────────────────────
KNOWN_PROVIDERS = {
    "160.79.106.": {"provider": "Anthropic", "platform": "claude.ai", "note": "Claude.ai MCP operator"},
    "192.168.13.37": {"provider": "Anthropic", "platform": "claude-desktop", "note": "Claude Desktop (local)"},
}
KNOWN_USER_AGENTS = {
    "Claude-User": {"provider": "Anthropic", "platform": "claude.ai"},
    "Claude-Desktop": {"provider": "Anthropic", "platform": "claude-desktop"},
}

def identify_provider_from_ip(ip: str) -> dict:
    if not ip: return {}
    for prefix, info in KNOWN_PROVIDERS.items():
        if ip.startswith(prefix) or ip == prefix: return dict(info)
    return {}

def identify_provider_from_ua(user_agent: str) -> dict:
    if not user_agent: return {}
    for ua_pattern, info in KNOWN_USER_AGENTS.items():
        if ua_pattern in user_agent: return dict(info)
    if "axios/" in user_agent: return {"client_lib": "axios", "runtime": "node.js"}
    if "python-httpx/" in user_agent: return {"client_lib": "python-httpx", "runtime": "python"}
    if "curl/" in user_agent: return {"client_lib": "curl", "runtime": "cli"}
    if "Go-http-client/" in user_agent: return {"client_lib": "go-http", "runtime": "go"}
    return {}


# ─── Session Tracking ────────────────────────────────────────────────────────
_session_state = defaultdict(lambda: {
    "call_seq": 0,
    "tools_called": [],
    "resources_accessed": [],
    "reasoning_log": [],
    "feedback_log": [],
    "findings_reported": [],
    "first_seen": None,
    "last_seen": None,
    "client_info": {},
    "protocol_version": "",
    "client_capabilities": {},
    "user_agent": "",
    "provider_guess": {},
    "model_info": "",
})
_session_lock = threading.Lock()


def get_session_state(session_id: str) -> dict:
    with _session_lock:
        state = _session_state[session_id or "unknown"]
        if state["first_seen"] is None:
            state["first_seen"] = datetime.now(timezone.utc).isoformat()
        state["last_seen"] = datetime.now(timezone.utc).isoformat()
        return state


def register_client_info(session_id: str, initialize_params: dict, source_ip: str = "", user_agent: str = ""):
    state = get_session_state(session_id)
    with _session_lock:
        client_info = initialize_params.get("clientInfo", {})
        state["client_info"] = {"name": client_info.get("name", ""), "version": client_info.get("version", "")}
        state["protocol_version"] = initialize_params.get("protocolVersion", "")
        state["client_capabilities"] = initialize_params.get("capabilities", {})
        state["user_agent"] = user_agent
        provider = identify_provider_from_ip(source_ip)
        if not provider: provider = identify_provider_from_ua(user_agent)
        state["provider_guess"] = provider

    record = {
        "_type": "client_identified", "_ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id, "source_ip": source_ip, "user_agent": user_agent,
        "mcp_client_name": client_info.get("name", ""), "mcp_client_version": client_info.get("version", ""),
        "mcp_protocol_version": initialize_params.get("protocolVersion", ""),
        "mcp_capabilities": initialize_params.get("capabilities", {}),
        "provider_guess": state["provider_guess"], "raw_initialize_params": initialize_params,
    }
    for logfile in ("langfuse-traces.jsonl", "llm-reasoning.jsonl"):
        try:
            with open(os.path.join(LOG_DIR, logfile), "a") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except Exception: pass

    logger.info(f"Client identified: {client_info.get('name','?')}/{client_info.get('version','?')} "
                f"proto={initialize_params.get('protocolVersion','')} "
                f"from {source_ip} ({state['provider_guess'].get('provider','unknown')})")


def advance_session(session_id: str, tool_name: str, arguments: dict) -> int:
    state = get_session_state(session_id)
    with _session_lock:
        state["call_seq"] += 1
        seq = state["call_seq"]
        state["tools_called"].append({"seq": seq, "tool": tool_name, "ts": datetime.now(timezone.utc).isoformat()})
        reasoning = arguments.get("reasoning", "")
        if reasoning:
            state["reasoning_log"].append({"seq": seq, "tool": tool_name, "reasoning": reasoning})
        feedback = arguments.get("feedback", "")
        if feedback:
            state["feedback_log"].append({"seq": seq, "tool": tool_name, "feedback": feedback})
        model_info = arguments.get("model_info", "")
        if model_info and not state["model_info"]:
            state["model_info"] = model_info
        resource = (
            arguments.get("query", "") or arguments.get("path", "") or
            arguments.get("pattern", "") or arguments.get("table_name", "") or
            arguments.get("command", "")
        )
        if resource:
            state["resources_accessed"].append(resource[:200])
    return seq


def _build_client_fields(session_id: str) -> dict:
    state = get_session_state(session_id)
    return {
        "client_name": state["client_info"].get("name", ""),
        "client_version": state["client_info"].get("version", ""),
        "protocol_version": state["protocol_version"],
        "user_agent": state["user_agent"],
        "provider_guess": state["provider_guess"],
        "model_info": state["model_info"],
    }


def _get_langfuse():
    global _langfuse
    if _langfuse is None and LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY:
        try:
            from langfuse import Langfuse
            _langfuse = Langfuse(
                public_key=LANGFUSE_PUBLIC_KEY, secret_key=LANGFUSE_SECRET_KEY,
                host=LANGFUSE_HOST, flush_at=1, flush_interval=5,
            )
            logger.info("Langfuse client initialized")
        except Exception as e:
            logger.warning(f"Langfuse init failed (JSONL-only mode): {e}")
    return _langfuse


def trace_mcp_call(
    server_name: str, tool_name: str, arguments: dict, result_text: str,
    source_ip: str = None, session_id: str = None, duration_ms: float = None,
    is_error: bool = False, error_msg: str = None,
):
    seq = advance_session(session_id, tool_name, arguments)
    state = get_session_state(session_id)
    client = _build_client_fields(session_id)

    reasoning = arguments.get("reasoning", "")
    context = arguments.get("context", "")
    objective = arguments.get("objective", "")
    model_info = arguments.get("model_info", "")
    feedback = arguments.get("feedback", "")

    record = {
        "_type": "langfuse_trace", "_ts": datetime.now(timezone.utc).isoformat(),
        "server": server_name, "tool": tool_name, "arguments": arguments,
        "result_length": len(result_text) if result_text else 0,
        "result_preview": (result_text[:1000] if result_text else ""),
        "source_ip": source_ip, "session_id": session_id,
        "duration_ms": duration_ms, "is_error": is_error, "error": error_msg,
        "reasoning": reasoning, "context": context, "objective": objective,
        "feedback": feedback,
        "call_seq": seq, "session_tool_count": state["call_seq"],
        "session_tools_so_far": [t["tool"] for t in state["tools_called"]],
        **client,
    }
    try:
        with open(os.path.join(LOG_DIR, "langfuse-traces.jsonl"), "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception: pass

    # Write to reasoning log if any enrichment fields present
    if reasoning or context or objective or model_info or feedback:
        rr = {
            "_type": "llm_reasoning", "_ts": datetime.now(timezone.utc).isoformat(),
            "server": server_name, "tool": tool_name, "call_seq": seq,
            "session_id": session_id, "source_ip": source_ip,
            "reasoning": reasoning, "context": context, "objective": objective,
            "model_info": model_info, "feedback": feedback,
            "session_history": [t["tool"] for t in state["tools_called"]],
            **client,
        }
        try:
            with open(os.path.join(LOG_DIR, "llm-reasoning.jsonl"), "a") as f:
                f.write(json.dumps(rr, default=str) + "\n")
        except Exception: pass

    # Write dedicated feedback log entry if feedback is present
    if feedback:
        fb = {
            "_type": "llm_feedback", "_ts": datetime.now(timezone.utc).isoformat(),
            "server": server_name, "tool": tool_name, "call_seq": seq,
            "session_id": session_id, "source_ip": source_ip,
            "feedback": feedback, "model_info": model_info,
            "session_tool_count": state["call_seq"],
            **client,
        }
        try:
            with open(os.path.join(LOG_DIR, "llm-feedback.jsonl"), "a") as f:
                f.write(json.dumps(fb, default=str) + "\n")
        except Exception: pass

    lf = _get_langfuse()
    if lf is None: return
    try:
        tr = lf.trace(
            name=f"mcp-{tool_name}", session_id=session_id or "unknown",
            user_id=source_ip or "unknown",
            metadata={"server": server_name, "source_ip": source_ip, "reasoning": reasoning,
                      "feedback": feedback, "call_seq": seq, **client},
            tags=["platform", "mcp", server_name, tool_name],
        )
        tr.generation(
            name=tool_name, input=arguments,
            output=result_text[:2000] if result_text else "",
            model=client.get("model_info") or client.get("client_name") or f"mcp-tool/{server_name}",
            metadata={"source_ip": source_ip, "session_id": session_id, "error": error_msg,
                      "reasoning": reasoning, "feedback": feedback, "call_seq": seq, **client},
            usage={"input": len(json.dumps(arguments)) if arguments else 0,
                   "output": len(result_text) if result_text else 0},
            level="ERROR" if is_error else "DEFAULT",
            status_message=error_msg if error_msg else "success",
        )
        lf.flush()
    except Exception as e:
        logger.debug(f"Langfuse trace send failed: {e}")


def trace_finding(server_name, finding, source_ip=None, session_id=None):
    state = get_session_state(session_id)
    client = _build_client_fields(session_id)
    with _session_lock:
        state["findings_reported"].append(finding)
    record = {
        "_type": "llm_finding", "_ts": datetime.now(timezone.utc).isoformat(),
        "server": server_name, "source_ip": source_ip, "session_id": session_id,
        "finding": finding, "session_tool_count": state["call_seq"],
        "session_tools_used": [t["tool"] for t in state["tools_called"]],
        "session_reasoning_log": state["reasoning_log"],
        "session_feedback_log": state["feedback_log"],
        "session_resources_accessed": state["resources_accessed"],
        **client,
    }
    for logfile in ("llm-reasoning.jsonl", "langfuse-traces.jsonl"):
        try:
            ltype = "llm_finding" if "reasoning" in logfile else "langfuse_finding"
            with open(os.path.join(LOG_DIR, logfile), "a") as f:
                f.write(json.dumps({**record, "_type": ltype}, default=str) + "\n")
        except Exception: pass


def trace_admin_command(command, output, source_ip=None, session_id=None, exit_code=None, duration_ms=None):
    record = {
        "_type": "langfuse_admin_trace", "_ts": datetime.now(timezone.utc).isoformat(),
        "server": "aicryptovault-admin", "command": command,
        "output_length": len(output) if output else 0,
        "output_preview": (output[:1000] if output else ""),
        "source_ip": source_ip, "session_id": session_id,
        "exit_code": exit_code, "duration_ms": duration_ms,
    }
    try:
        with open(os.path.join(LOG_DIR, "langfuse-traces.jsonl"), "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception: pass
