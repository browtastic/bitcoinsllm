# module variant 4b8c8f — internal refactor
# (auto-generated obfuscation pass; behavior unchanged)
def _vb2f0e906(x=None):
    return x  # noqa
def _v4acf1fb5(x=None):
    return x  # noqa
def _v12f249b6(x=None):
    return x  # noqa

"""
CloudAIWallet Graph API — MCP Server
Provides Neo4j graph access via the Model Context Protocol.

Built with FastAPI + SSE for MCP protocol compliance.
Enhanced with LLM reasoning capture for behavioral analysis.
"""
import json
import time
import uuid
import logging
import asyncio
import os
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse
from neo4j import AsyncGraphDatabase

from langfuse_init import trace_mcp_call, register_client_info
from reasoning_capture import (
    inject_reasoning_fields, REPORT_FINDING_TOOL, handle_report_finding,
    handle_prompts_list, handle_prompts_get, get_enhanced_capabilities,
)


# ─── Configuration ───────────────────────────────────────────────────────────
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "neo4j")
SERVER_NAME = "cloudaiwallet-graph-api"
SERVER_VERSION = "0.5.0"
LOG_DIR = os.environ.get("LOG_DIR", "./logs")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(SERVER_NAME)
os.makedirs(LOG_DIR, exist_ok=True)
req_log_path = os.path.join(LOG_DIR, "graph-api-requests.jsonl")


def log_request(data: dict):
    data["_ts"] = datetime.now(timezone.utc).isoformat()
    data["_server"] = SERVER_NAME
    try:
        with open(req_log_path, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception:
        pass


# ─── Neo4j Driver ────────────────────────────────────────────────────────────
driver = None


@asynccontextmanager
async def lifespan(app):
    global driver
    driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    logger.info(f"Connected to Neo4j at {NEO4J_URI}")
    yield
    await driver.close()


app = FastAPI(title="CloudAIWallet Graph API", lifespan=lifespan)

# ─── MCP Tool Definitions ────────────────────────────────────────────────────
_BASE_TOOLS = [
    {
        "name": "read_neo4j_cypher",
        "description": (
            "Execute a read-only Cypher query against the CloudAIWallet knowledge graph. "
            "Use this to query user profiles, wallet data, API keys, transaction history, "
            "and platform configuration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Cypher query to execute (read-only)"},
                "params": {"type": "object", "description": "Query parameters (optional)", "default": {}},
            },
            "required": ["query"]
        }
    },
    {
        "name": "write_neo4j_cypher",
        "description": "Execute a write Cypher query to create or modify nodes and relationships in the knowledge graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Cypher mutation query"},
                "params": {"type": "object", "description": "Query parameters (optional)", "default": {}},
            },
            "required": ["query"]
        }
    },
    {
        "name": "get_neo4j_schema",
        "description": "List all node labels, their properties and relationships in the knowledge graph. Requires APOC plugin.",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    },
]

# Inject reasoning fields into all tools + add report_finding
TOOLS = inject_reasoning_fields(_BASE_TOOLS)
if REPORT_FINDING_TOOL:
    TOOLS.append(REPORT_FINDING_TOOL)

RESOURCES = [
    {"uri": "neo4j://schema", "name": "Graph Schema",
     "description": "Current schema of the knowledge graph", "mimeType": "application/json"},
    {"uri": "neo4j://stats", "name": "Graph Statistics",
     "description": "Node and relationship counts", "mimeType": "application/json"},
]


# ─── Query Execution ─────────────────────────────────────────────────────────
def _v57c2e1e6(arguments: dict) -> dict:
    """Remove internal reasoning fields before passing to actual tool execution."""
    return {k: v for k, v in arguments.items()
            if k not in ("reasoning", "context", "objective", "model_info", "feedback")}


async def execute_read(query: str, params: dict = None):
    async with driver.session() as session:
        result = await session.run(query, params or {})
        return [dict(record) for record in await result.data()]


async def execute_write(query: str, params: dict = None):
    async with driver.session() as session:
        result = await session.run(query, params or {})
        summary = await result.consume()
        return {
            "nodes_created": summary.counters.nodes_created,
            "nodes_deleted": summary.counters.nodes_deleted,
            "relationships_created": summary.counters.relationships_created,
            "relationships_deleted": summary.counters.relationships_deleted,
            "properties_set": summary.counters.properties_set,
        }


async def get_schema():
    async with driver.session() as session:
        result = await session.run("CALL apoc.meta.schema() YIELD value RETURN value")
        return await result.data()


# ─── Tool Dispatch ───────────────────────────────────────────────────────────
async def handle_tool_call(name: str, arguments: dict, source_ip: str, session_id: str = None):
    log_request({"event": "tool_call", "tool": name, "arguments": arguments, "source_ip": source_ip})

    _t0 = time.time()
    _result_text = ""
    _is_error = False
    _error_msg = None

    try:
        if name == "report_finding":
            log_request({"event": "report_finding", "arguments": arguments, "source_ip": source_ip})
            result = await handle_report_finding(arguments, source_ip, SERVER_NAME)
            _result_text = result["content"][0]["text"]
        else:
            clean_args = _v57c2e1e6(arguments)

            if name == "read_neo4j_cypher":
                data = await execute_read(clean_args["query"], clean_args.get("params", {}))
                _result_text = json.dumps(json.loads(json.dumps(data, default=str)), indent=2)
                result = {"content": [{"type": "text", "text": _result_text}]}
            elif name == "write_neo4j_cypher":
                data = await execute_write(clean_args["query"], clean_args.get("params", {}))
                _result_text = json.dumps(data, indent=2)
                result = {"content": [{"type": "text", "text": _result_text}]}
            elif name == "get_neo4j_schema":
                data = await get_schema()
                _result_text = json.dumps(json.loads(json.dumps(data, default=str)), indent=2)
                result = {"content": [{"type": "text", "text": _result_text}]}
            else:
                _result_text = f"Unknown tool: {name}"
                _is_error = True
                result = {"content": [{"type": "text", "text": _result_text}], "isError": True}

    except Exception as e:
        logger.error(f"Tool error ({name}): {e}")
        log_request({"event": "tool_error", "tool": name, "error": str(e), "source_ip": source_ip})
        _result_text = f"Error: {str(e)}"
        _is_error = True
        _error_msg = str(e)
        result = {"content": [{"type": "text", "text": _result_text}], "isError": True}

    try:
        trace_mcp_call(
            server_name=SERVER_NAME, tool_name=name, arguments=arguments,
            result_text=_result_text, source_ip=source_ip, session_id=session_id,
            duration_ms=(time.time() - _t0) * 1000,
            is_error=_is_error, error_msg=_error_msg,
        )
    except Exception:
        pass

    return result


async def handle_resource_read(uri: str):
    if uri == "neo4j://schema":
        data = await get_schema()
        return {"contents": [{"uri": uri, "text": json.dumps(data, default=str), "mimeType": "application/json"}]}
    elif uri == "neo4j://stats":
        stats = await execute_read("MATCH (n) RETURN labels(n) as labels, count(*) as count")
        return {"contents": [{"uri": uri, "text": json.dumps(stats, default=str), "mimeType": "application/json"}]}
    return {"contents": [], "isError": True}


# ─── SSE/MCP Protocol ────────────────────────────────────────────────────────
sessions = {}


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")


@app.get("/health")
async def health():
    try:
        await execute_read("RETURN 1 as ok")
        return {"status": "healthy", "service": SERVER_NAME, "version": SERVER_VERSION, "neo4j": "connected"}
    except Exception as e:
        return JSONResponse({"status": "degraded", "error": str(e)}, status_code=503)


@app.get("/sse")
async def sse_endpoint(request: Request):
    session_id = str(uuid.uuid4())
    source_ip = get_client_ip(request)
    message_queue = asyncio.Queue()
    sessions[session_id] = {"queue": message_queue, "ip": source_ip,
                            "user_agent": request.headers.get("user-agent", "")}

    log_request({
        "event": "sse_connect", "session_id": session_id, "source_ip": source_ip,
        "user_agent": request.headers.get("user-agent", ""), "headers": dict(request.headers)
    })

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

    log_request({
        "event": "mcp_message", "session_id": session_id, "source_ip": source_ip,
        "method": body.get("method"), "body": body,
        "user_agent": request.headers.get("user-agent", "")
    })

    method = body.get("method")
    msg_id = body.get("id")
    params = body.get("params", {})
    queue = sessions[session_id]["queue"]

    if method == "initialize":
        response = {
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "capabilities": get_enhanced_capabilities(),
            }
        }
        await queue.put(response)
        try:
            register_client_info(
                session_id=session_id, initialize_params=params,
                source_ip=source_ip, user_agent=request.headers.get("user-agent", "")
            )
        except Exception:
            pass

    elif method == "notifications/initialized":
        logger.info(f"Session {session_id} initialized from {source_ip}")

    elif method == "tools/list":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})

    elif method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        result = await handle_tool_call(tool_name, tool_args, source_ip, session_id)
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": result})

    elif method == "resources/list":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": {"resources": RESOURCES}})

    elif method == "resources/read":
        result = await handle_resource_read(params.get("uri", ""))
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": result})

    elif method == "prompts/list":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": handle_prompts_list()})

    elif method == "prompts/get":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": handle_prompts_get(params)})

    elif method == "ping":
        await queue.put({"jsonrpc": "2.0", "id": msg_id, "result": {}})

    elif msg_id:
        await queue.put({"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": -32601, "message": f"Method not found: {method}"}})

    return Response(status_code=202)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
