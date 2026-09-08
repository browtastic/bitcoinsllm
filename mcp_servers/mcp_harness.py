#!/usr/bin/env python3
"""
mcp_harness.py — shared MCP-over-SSE transport for the AI-CVE bait servers.

The existing servers (database_api etc.) each carry their own copy of the SSE
transport. Rather than duplicate ~80 lines into 5 new files, the AI-CVE servers
import this and call run(). Same protocol: GET /sse opens a session and hands back
/messages?sessionId=..., POST /messages drives JSON-RPC (initialize / tools/list /
tools/call / ping). Matches the existing servers so real MCP clients + OpenClaw work.

Also emits a tool_call event to the unified acv_log pipeline (so these servers show
up in /var/log/acv/events.jsonl like the converted ones).

A server module provides: SERVER_INFO (dict), _BASE_TOOLS (list),
handle_tool_call(name, arguments, source_ip, session_id) -> result dict.

Usage (at the bottom of each server file):
    from mcp_harness import run
    if __name__ == "__main__":
        run(__import__(__name__))   # or run(sys.modules[__name__])
"""
import asyncio
import json
import os
import time
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

try:
    import acv_log
except Exception:
    class _Stub:
        @staticmethod
        def emit(*a, **k): return None
    acv_log = _Stub()


def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def build_app(mod):
    app = FastAPI()
    sessions = {}
    info = getattr(mod, "SERVER_INFO", {"name": "mcp-server", "version": "1.0.0"})
    tools = getattr(mod, "_BASE_TOOLS", [])
    handle = getattr(mod, "handle_tool_call")
    server_label = os.environ.get("ACV_SERVER", info.get("name", "mcp-server"))

    @app.get("/health")
    async def health():
        return {"status": "ok", "server": info.get("name"), "active_sessions": len(sessions)}

    @app.get("/sse")
    async def sse_endpoint(request: Request):
        session_id = str(uuid.uuid4())
        source_ip = get_client_ip(request)
        sessions[session_id] = {"queue": asyncio.Queue(), "source_ip": source_ip}

        async def event_generator():
            try:
                yield {"event": "endpoint", "data": f"/messages?sessionId={session_id}"}
                q = sessions[session_id]["queue"]
                while True:
                    try:
                        msg = await asyncio.wait_for(q.get(), timeout=30)
                        yield {"event": "message", "data": json.dumps(msg)}
                    except asyncio.TimeoutError:
                        yield {"event": "ping", "data": ""}
                    except asyncio.CancelledError:
                        break
            finally:
                sessions.pop(session_id, None)
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

        method = body.get("method")
        msg_id = body.get("id")
        params = body.get("params", {}) or {}
        q = sessions[session_id]["queue"]

        if method == "initialize":
            await q.put({"jsonrpc": "2.0", "id": msg_id, "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": info.get("name"), "version": info.get("version")},
                "capabilities": {"tools": {"listChanged": False}}}})
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            await q.put({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}})
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {}) or {}
            _t0 = time.time()
            result = await handle(name, arguments, source_ip, session_id)
            # unified pipeline emit (never raises)
            try:
                _rt = ""
                if isinstance(result, dict):
                    c = (result.get("content") or [{}])
                    _rt = c[0].get("text", "") if c else ""
                acv_log.emit("tool_call", {
                    "tool": name, "arguments": arguments,
                    "result_preview": str(_rt)[:500], "result_length": len(str(_rt)),
                    "duration_ms": (time.time() - _t0) * 1000,
                    "is_error": bool(isinstance(result, dict) and result.get("isError")),
                    "reasoning": arguments.get("reasoning"),
                    "objective": arguments.get("objective"),
                }, source_ip=source_ip, session_id=session_id,
                   client_name=arguments.get("client_application"))
            except Exception:
                pass
            await q.put({"jsonrpc": "2.0", "id": msg_id, "result": result})
        elif method == "ping":
            await q.put({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        elif msg_id:
            await q.put({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": -32601, "message": f"Unknown: {method}"}})
        return Response(status_code=202)

    return app


def run(mod):
    import uvicorn
    app = build_app(mod)
    port = int(os.environ.get("PORT", "8093"))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port, log_level="info")
