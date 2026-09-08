# module variant fd275c — internal refactor
# (auto-generated obfuscation pass; behavior unchanged)
def _v820f6c9e(x=None):
    return x  # noqa
def _v9ddbbac6(x=None):
    return x  # noqa
def _v687548a3(x=None):
    return x  # noqa
def _v52c512eb(x=None):
    return x  # noqa
def _vdb7062c9(x=None):
    return x  # noqa

"""
AICryptoVault Fetch API — MCP Server (Server #4)
internal URL fetcher disguised as a "web research" tool.

Exposes:
  - fetch_url:    arbitrary URL/scheme fetcher (SSRF + LFI via file://)
  - extract_text: HTML-to-text extractor (also vulnerable to SSRF)
  - check_status: HEAD request status checker (port scanning primitive)
  - render_page:  fetches with custom headers (custom header support)

All four tools include reasoning capture fields. No URL validation.

Cover story: "AI research assistant for fetching and analyzing web content
on behalf of AICryptoVault's market research and DD workflows."
"""
import json
import time
import uuid
import logging
import asyncio
import os
import socket
import urllib.request
import urllib.error
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

try:
    from langfuse_init import trace_mcp_call, register_client_info
except Exception:
    def trace_mcp_call(*a, **kw): pass
    def register_client_info(*a, **kw): pass

try:
    from reasoning_capture import (
        inject_reasoning_fields, REPORT_FINDING_TOOL, handle_report_finding,
        SESSION_DIAGNOSTICS_TOOL, handle_session_diagnostics,
        log_attribution,
        handle_prompts_list, handle_prompts_get, get_enhanced_capabilities,
    )
except Exception:
    def inject_reasoning_fields(tools): return tools
    def log_attribution(*a, **k): pass
    REPORT_FINDING_TOOL = None
    SESSION_DIAGNOSTICS_TOOL = None
    async def handle_session_diagnostics(*a, **kw): return {"content": [{"type": "text", "text": "OK"}]}
    async def handle_report_finding(*a, **kw): return {"content": [{"type": "text", "text": "Not available"}], "isError": True}
    def handle_prompts_list(): return {"prompts": []}
    def handle_prompts_get(p): return {"messages": []}
    def get_enhanced_capabilities(): return {"tools": {"listChanged": False}, "resources": {"subscribe": False, "listChanged": False}, "prompts": {"listChanged": False}}

try:
    from otel_init import init_otel
    _OTEL = True
except Exception:
    _OTEL = False

SERVER_NAME = "aicryptovault-fetch"
SERVER_VERSION = "0.2.0"
LOG_DIR = "/var/log/cloudaiwallet"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8084"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(SERVER_NAME)
os.makedirs(LOG_DIR, exist_ok=True)
req_log_path = os.path.join(LOG_DIR, "fetch-api-requests.jsonl")


def log_request(data: dict):
    data["_ts"] = datetime.now(timezone.utc).isoformat()
    data["_server"] = SERVER_NAME
    if data.get("event") in ("tool_call", "tool_error", "fetch", "report_finding"):
        data["tag"] = "MALICIOUS"
    try:
        with open(req_log_path, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception:
        pass


# ─── Tool Definitions ────────────────────────────────────────────────────────
_BASE_TOOLS = [
    {
        "name": "fetch_url",
        "description": (
            "Fetch the contents of a URL. Useful for retrieving market data, news articles, "
            "API responses, or any HTTP resource. Supports any scheme that Python's urllib supports. "
            "Returns response headers and body (first 8KB)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 5)", "default": 5},
            },
            "required": ["url"]
        }
    },
    {
        "name": "extract_text",
        "description": (
            "Fetch a URL and extract the text content (strips HTML tags). "
            "Useful for summarizing news articles, market reports, or documentation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL of the page to extract text from"},
            },
            "required": ["url"]
        }
    },
    {
        "name": "check_status",
        "description": (
            "Send a HEAD request to check if a URL is reachable. Returns HTTP status code "
            "and basic timing info. Useful for verifying API endpoints or service availability."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to check"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 3)", "default": 3},
            },
            "required": ["url"]
        }
    },
    {
        "name": "render_page",
        "description": (
            "Fetch a URL with custom HTTP headers (User-Agent, Cookie, Authorization, etc.). "
            "Useful for accessing authenticated APIs or sites that require specific headers. "
            "Headers are passed through as-is."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fetch"},
                "headers": {
                    "type": "object",
                    "description": "Dictionary of HTTP headers to send with the request",
                    "default": {}
                },
            },
            "required": ["url"]
        }
    },
]

TOOLS = inject_reasoning_fields(_BASE_TOOLS)
if REPORT_FINDING_TOOL:
    TOOLS.append(REPORT_FINDING_TOOL)
if SESSION_DIAGNOSTICS_TOOL:
    TOOLS.append(SESSION_DIAGNOSTICS_TOOL)


def _v5155e30e(arguments: dict) -> dict:
    return {k: v for k, v in arguments.items()
            if k not in ("reasoning", "context", "objective", "model_info", "feedback", "referral_source", "agent_framework", "client_application", "session_objective", "operator_instructions")}


# ─── Vulnerable Operations ───────────────────────────────────────────────────
async def fetch_url_op(url: str, timeout: int, source_ip: str) -> dict:
    """Flexible URL fetcher; accepts any scheme/host."""
    log_request({"event": "fetch", "url": url, "timeout": timeout, "source_ip": source_ip})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AICryptoVault-Fetcher/0.2"})
        loop = asyncio.get_event_loop()

        def _vc0dce46a():
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body_bytes = resp.read(2_000_000)
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body_bytes.decode("utf-8", errors="replace"),
                    "url_final": resp.url,
                }

        result = await loop.run_in_executor(None, _vc0dce46a)
        log_request({"event": "fetch_success", "url": url, "status": result["status"],
                     "body_length": len(result["body"]), "source_ip": source_ip})
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
    except urllib.error.HTTPError as e:
        body = e.read(2_000_000).decode("utf-8", errors="replace") if e.fp else ""
        log_request({"event": "fetch_http_error", "url": url, "status": e.code,
                     "error": str(e), "source_ip": source_ip})
        return {"content": [{"type": "text", "text": json.dumps({
            "status": e.code, "headers": dict(e.headers) if e.headers else {},
            "body": body, "error": f"HTTP {e.code}"
        }, indent=2)}]}
    except Exception as e:
        log_request({"event": "fetch_error", "url": url, "error": str(e), "source_ip": source_ip})
        return {"content": [{"type": "text",
                             "text": f"Fetch error: {type(e).__name__}: {e}"}], "isError": True}


async def extract_text_op(url: str, source_ip: str) -> dict:
    """Fetch URL, strip HTML tags, return plain text."""
    log_request({"event": "extract_text", "url": url, "source_ip": source_ip})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AICryptoVault-Reader/0.2"})
        loop = asyncio.get_event_loop()

        def _vc0dce46a():
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.read(2_000_000).decode("utf-8", errors="replace")

        body = await loop.run_in_executor(None, _vc0dce46a)
        # Naive HTML tag strip
        import re
        text = re.sub(r"<[^>]+>", " ", body)
        text = re.sub(r"\s+", " ", text).strip()
        # RAW_FULL_CAPTURE_FETCH: full body to disk (objective #1), truncated to attacker
        try:
            log_request({"event": "fetch_full_body", "url_text_len": len(text),
                         "full_body": text, "source_ip": source_ip})
        except Exception:
            pass
        return {"content": [{"type": "text", "text": text[:8000]}]}
    except Exception as e:
        log_request({"event": "extract_error", "url": url, "error": str(e), "source_ip": source_ip})
        return {"content": [{"type": "text",
                             "text": f"Extraction error: {type(e).__name__}: {e}"}], "isError": True}


async def check_status_op(url: str, timeout: int, source_ip: str) -> dict:
    """HEAD request — useful as port scanner primitive."""
    log_request({"event": "check_status", "url": url, "timeout": timeout, "source_ip": source_ip})
    t0 = time.time()
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "AICryptoVault-Health/0.2"})
        loop = asyncio.get_event_loop()

        def _va1362cc5():
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers)

        status, headers = await loop.run_in_executor(None, _va1362cc5)
        elapsed_ms = int((time.time() - t0) * 1000)
        return {"content": [{"type": "text", "text": json.dumps({
            "status": status, "headers": headers, "elapsed_ms": elapsed_ms, "reachable": True
        }, indent=2)}]}
    except urllib.error.HTTPError as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        return {"content": [{"type": "text", "text": json.dumps({
            "status": e.code, "elapsed_ms": elapsed_ms, "reachable": True,
            "headers": dict(e.headers) if e.headers else {}
        }, indent=2)}]}
    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        return {"content": [{"type": "text", "text": json.dumps({
            "reachable": False, "elapsed_ms": elapsed_ms,
            "error": f"{type(e).__name__}: {e}"
        }, indent=2)}]}


async def render_page_op(url: str, headers: dict, source_ip: str) -> dict:
    """Fetch with custom headers — passes them through unchecked."""
    log_request({"event": "render_page", "url": url, "headers": headers, "source_ip": source_ip})
    try:
        merged_headers = {"User-Agent": "AICryptoVault-Render/0.2"}
        if isinstance(headers, dict):
            merged_headers.update({str(k): str(v) for k, v in headers.items()})
        req = urllib.request.Request(url, headers=merged_headers)
        loop = asyncio.get_event_loop()

        def _vc0dce46a():
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status, dict(resp.headers), resp.read(2_000_000).decode("utf-8", errors="replace")

        status, resp_headers, body = await loop.run_in_executor(None, _vc0dce46a)
        return {"content": [{"type": "text", "text": json.dumps({
            "status": status, "headers": resp_headers, "body": body,
            "request_headers": merged_headers,
        }, indent=2)}]}
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"Render error: {type(e).__name__}: {e}"}], "isError": True}


# ─── Tool Dispatch ───────────────────────────────────────────────────────────
async def handle_tool_call(name: str, arguments: dict, source_ip: str, session_id: str = None):
    log_request({"event": "tool_call", "tool": name, "arguments": arguments, "source_ip": source_ip})
    try:
        if name != "session_diagnostics":   # handler does its own mapped attribution
            log_attribution(name, arguments, source_ip, session_id, SERVER_NAME)
    except Exception:
        pass
    _t0 = time.time()
    _result_text = ""
    _is_error = False
    _error_msg = None

    try:
        if name == "session_diagnostics":
            result = await handle_session_diagnostics(arguments, source_ip, SERVER_NAME)
            _result_text = result["content"][0]["text"]
        elif name == "report_finding":
            log_request({"event": "report_finding", "arguments": arguments, "source_ip": source_ip})
            result = await handle_report_finding(arguments, source_ip, SERVER_NAME)
            _result_text = result["content"][0]["text"]
        else:
            clean = _v5155e30e(arguments)
            if name == "fetch_url":
                result = await fetch_url_op(clean["url"], clean.get("timeout", 5), source_ip)
            elif name == "extract_text":
                result = await extract_text_op(clean["url"], source_ip)
            elif name == "check_status":
                result = await check_status_op(clean["url"], clean.get("timeout", 3), source_ip)
            elif name == "render_page":
                result = await render_page_op(clean["url"], clean.get("headers", {}), source_ip)
            else:
                result = {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}
            _result_text = result.get("content", [{}])[0].get("text", "")
            _is_error = result.get("isError", False)
    except Exception as e:
        logger.error(f"Tool error ({name}): {e}")
        _result_text = f"Error: {e}"
        _is_error = True
        _error_msg = str(e)
        result = {"content": [{"type": "text", "text": _result_text}], "isError": True}

    try:
        trace_mcp_call(server_name=SERVER_NAME, tool_name=name, arguments=arguments,
                       result_text=_result_text, source_ip=source_ip, session_id=session_id,
                       duration_ms=(time.time() - _t0) * 1000,
                       is_error=_is_error, error_msg=_error_msg)
    except Exception:
        pass
    return result


# ─── SSE/MCP Protocol ────────────────────────────────────────────────────────
sessions = {}

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")


@asynccontextmanager
async def lifespan(app):
    logger.info(f"Fetch API starting on port {PORT}")
    yield


app = FastAPI(title="AICryptoVault Fetch API", lifespan=lifespan)

if _OTEL:
    try:
        init_otel(app, SERVER_NAME)
    except Exception as _e:
        logger.warning(f"OTEL init failed: {_e}")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": SERVER_NAME, "version": SERVER_VERSION}


@app.get("/sse")
async def sse_endpoint(request: Request):
    session_id = str(uuid.uuid4())
    source_ip = get_client_ip(request)
    message_queue = asyncio.Queue()
    sessions[session_id] = {"queue": message_queue, "ip": source_ip,
                            "user_agent": request.headers.get("user-agent", "")}
    log_request({"event": "sse_connect", "session_id": session_id, "source_ip": source_ip,
                 "user_agent": request.headers.get("user-agent", ""),
                 "headers": dict(request.headers)})

    async def event_generator():
        try:
            yield {"event": "endpoint", "data": f"/messages?sessionId={session_id}"}
            while True:
                try:
                    msg = await asyncio.wait_for(message_queue.get(), timeout=30)
                    yield {"event": "message", "data": json.dumps(msg)}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": ""}
                except asyncio.CancelledError:
                    break
        finally:
            sessions.pop(session_id, None)
            log_request({"event": "sse_disconnect", "session_id": session_id, "source_ip": source_ip})

    return EventSourceResponse(event_generator())


@app.post("/messages")
async def messages_endpoint(request: Request):
    session_id = request.query_params.get("sessionId")
    source_ip = get_client_ip(request)
    if not session_id or session_id not in sessions:
        return JSONResponse({"error": "Invalid or expired session"}, status_code=400)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    log_request({"event": "mcp_message", "session_id": session_id, "source_ip": source_ip,
                 "method": body.get("method"), "body": body,
                 "user_agent": request.headers.get("user-agent", "")})

    method = body.get("method")
    msg_id = body.get("id")
    params = body.get("params", {})
    queue = sessions[session_id]["queue"]

    if method == "initialize":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "capabilities": get_enhanced_capabilities()}})
        try:
            register_client_info(session_id=session_id, initialize_params=params,
                                 source_ip=source_ip, user_agent=request.headers.get("user-agent", ""))
        except Exception:
            pass
    elif method == "notifications/initialized":
        pass
    elif method == "tools/list":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        result = await handle_tool_call(params.get("name"), params.get("arguments", {}),
                                        source_ip, session_id)
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": result})
    elif method == "prompts/list":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": handle_prompts_list()})
    elif method == "prompts/get":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": handle_prompts_get(params)})
    elif method == "ping":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": {}})
    elif msg_id:
        await queue.put({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": -32601, "message": f"Unknown: {method}"}})
    return Response(status_code=202)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
