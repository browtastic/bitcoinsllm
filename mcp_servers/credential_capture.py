"""
credential_capture.py  —  AICryptoVault honeypot

Capture any API keys / tokens an attacker presents to the honeypot, wherever
they appear: HTTP headers, URL query params, request bodies, MCP tool-call
arguments, and the injected reasoning-capture fields.

Emits a structured `credential_capture` log record (same envelope style as the
rest of the pipeline) plus an `ACV/Credentials` CloudWatch metric.

────────────────────────────────────────────────────────────────────────────
SAFETY POSTURE (read this — it is deliberate, not optional)

These are OTHER PEOPLE'S live secrets. Treat them like radioactive evidence:

  1. NEVER use a captured key. Never authenticate, "just validate", or call the
     provider with it — that is unauthorized access to the attacker's account
     and is itself a crime. This module never makes an outbound call with a
     captured value. `looks_live` is a FORMAT heuristic only; nothing is tested
     against a live service.
  2. Store redacted by default. The searchable record keeps provider + prefix
     + last4 + SHA-256 only. The full plaintext is kept ONLY if
     ACV_CRED_CAPTURE_FULL=1 AND a KMS key is configured, and even then it is
     KMS-encrypted into a separate field that needs elevated (off-box) access
     to read — mirroring the honeypot's write-only-on-box / read-off-box model.
  3. Optional, disabled by default: forward a captured key to the provider's
     abuse/leaked-key channel for REVOCATION (see report_for_revocation()).
     That is the one responsible "action" — it gets the key killed, it does
     not use it.
────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations
import os, re, json, time, base64, hashlib, logging
from collections import OrderedDict
from datetime import datetime, timezone

log = logging.getLogger("acv.credential_capture")

# ── config ──────────────────────────────────────────────────────────────────
CAPTURE_FULL = os.environ.get("ACV_CRED_CAPTURE_FULL", "0") == "1"
KMS_KEY_ID   = os.environ.get("ACV_CRED_KMS_KEY_ID")           # required for full capture
_DEDUP_MAX   = 4096                                            # remember recent hashes

# ── provider fingerprints ────────────────────────────────────────────────────
# (provider, key_type, regex). Order matters: most-specific first.
_PATTERNS = [
    ("anthropic",  "api_key",         re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("openai",     "project_key",     re.compile(r"sk-proj-[A-Za-z0-9\-_]{20,}")),
    ("openai",     "api_key",         re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("groq",       "api_key",         re.compile(r"gsk_[A-Za-z0-9]{40,}")),
    ("stripe",     "secret_key",      re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("aws",        "access_key_id",   re.compile(r"(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA)[A-Z0-9]{16}")),
    ("google",     "api_key",         re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("google",     "oauth_token",     re.compile(r"ya29\.[0-9A-Za-z\-_]{20,}")),
    ("github",     "pat",             re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github",     "token",           re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack",      "token",           re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("huggingface","token",           re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("npm",        "token",           re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("cohere",     "api_key",         re.compile(r"co-[A-Za-z0-9]{40,}")),
    ("jwt",        "json_web_token",  re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")),
    ("smithery",   "gateway_key",     re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("private_key","pem",             re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]
# Generic bearer/secret sweep — lower confidence, used only in auth-ish locations.
_GENERIC = re.compile(r"[A-Za-z0-9\-_]{32,}")

# ── redaction / hashing ───────────────────────────────────────────────────────
def _sha256(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8", "replace")).hexdigest()

def _redact(v: str) -> str:
    """provider-recognizable prefix + last4, middle masked."""
    if len(v) <= 8:
        return v[0] + "…" + v[-1]
    head = v[:6] if "-" in v[:6] or "_" in v[:6] else v[:4]
    return f"{head}…{v[-4:]}"

def _kms_encrypt(v: str):
    if not (CAPTURE_FULL and KMS_KEY_ID):
        return None
    try:
        import boto3
        ct = boto3.client("kms").encrypt(KeyId=KMS_KEY_ID, Plaintext=v.encode())["CiphertextBlob"]
        return base64.b64encode(ct).decode()
    except Exception as e:                       # never let capture break the request path
        log.warning("kms encrypt failed, storing redacted-only: %s", e)
        return None

# ── dedup (don't re-log the same key from the same session forever) ───────────
_seen: "OrderedDict[str,float]" = OrderedDict()
def _is_new(dedup_key: str) -> bool:
    now = time.time()
    if dedup_key in _seen:
        _seen.move_to_end(dedup_key); return False
    _seen[dedup_key] = now
    while len(_seen) > _DEDUP_MAX:
        _seen.popitem(last=False)
    return True

# ── recursive walk over arbitrary JSON-ish structures ─────────────────────────
def _walk(obj, path="$"):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    # ignore numbers/bools/None

# ── core matcher ──────────────────────────────────────────────────────────────
def _match_all(text: str, location: str):
    """Yield (provider, key_type, value) for every credential found in `text`."""
    hits = []
    for provider, ktype, rx in _PATTERNS:
        for m in rx.finditer(text):
            hits.append((provider, ktype, m.group(0)))
    if hits:
        return hits
    # only fall back to the noisy generic sweep in auth-ish locations
    if any(t in location.lower() for t in ("authorization", "api_key", "apikey",
                                           "token", "secret", "bearer", "x-api-key")):
        for m in _GENERIC.finditer(text):
            val = m.group(0)
            if val.lower() not in ("bearer", "basic", "authorization"):
                hits.append(("unknown", "opaque_token", val))
    return hits

# ── record builder + logger ───────────────────────────────────────────────────
def _emit(record: dict):
    """Write one credential_capture record to the pipeline + CloudWatch."""
    line = json.dumps(record, separators=(",", ":"))
    log.info(line)                               # goes to the same CloudWatch log group
    try:
        import acv_cloudwatch                     # reuse the existing shipper if present
        acv_cloudwatch.emit_log(record)
        acv_cloudwatch.put_metric("ACV/Credentials", "CredentialsCaptured", 1.0,
                                  dimensions={"provider": record["provider"]})
    except Exception:
        pass                                     # log line already emitted; metric is best-effort

def scan(payload, *, server="unknown", source_ip=None, session_id=None,
         location_hint="body", user_agent="", referer=""):
    """
    Scan any payload (str / dict / list) for credentials and log each new one.
    Returns the list of REDACTED records that were emitted (safe to keep in RAM).
    """
    out = []
    items = list(_walk(payload)) if not isinstance(payload, str) else [(location_hint, payload)]
    for path, text in items:
        if not text or len(text) < 12:
            continue
        loc = path if path != "$" else location_hint
        for provider, ktype, value in _match_all(text, loc):
            dedup = f"{session_id or source_ip}:{_sha256(value)}"
            if not _is_new(dedup):
                continue
            rec = {
                "_type": "credential_capture",
                "ts": datetime.now(timezone.utc).isoformat(),
                "server": server,
                "source_ip": source_ip,
                "session_id": session_id,
                "location": loc,                       # where in the request it was found
                "provider": provider,
                "key_type": ktype,
                "redacted": _redact(value),
                "sha256": _sha256(value),              # correlate/dedup without plaintext
                "length": len(value),
                "looks_live": _plausible(provider, value),   # FORMAT check only — never validated
                "user_agent": user_agent,
                "referer": referer,
            }
            enc = _kms_encrypt(value)
            if enc:
                rec["value_enc"] = enc                  # KMS ciphertext; off-box read only
            _emit(rec)
            out.append(rec)
    return out

def _plausible(provider: str, value: str) -> bool:
    """Cheap structural sanity check. NOT a liveness test against any provider."""
    if provider == "jwt":
        return value.count(".") == 2
    if provider == "aws":
        return len(value) == 20
    if provider in ("openai", "anthropic", "stripe", "google", "github",
                    "huggingface", "groq", "npm", "slack", "cohere"):
        return len(value) >= 24
    return len(value) >= 32

# ── FastAPI / Starlette middleware (graph/database/storage/fetch/database servers) ──
def install_fastapi(app, server_name: str):
    """
    Usage in each MCP server:
        from credential_capture import install_fastapi
        install_fastapi(app, "cloudaiwallet-graph-api")
    Scans headers + query string + JSON body of every inbound request.
    """
    from starlette.middleware.base import BaseHTTPMiddleware

    class _Mw(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                  or (request.client.host if request.client else None))
            ua = request.headers.get("user-agent", "")
            ref = request.headers.get("referer", "")
            # headers (Authorization, X-Api-Key, cookies…)
            for h in ("authorization", "x-api-key", "api-key", "x-auth-token", "cookie"):
                if h in request.headers:
                    scan(request.headers[h], server=server_name, source_ip=ip,
                         location_hint=f"http_header:{h}", user_agent=ua, referer=ref)
            # query string (Smithery ?api_key=…&profile=…)
            if request.url.query:
                scan(request.url.query, server=server_name, source_ip=ip,
                     location_hint="query_string", user_agent=ua, referer=ref)
            # body (best-effort; never blocks the request)
            try:
                body = await request.body()
                if body:
                    try:    payload = json.loads(body)
                    except Exception: payload = body.decode("utf-8", "replace")
                    scan(payload, server=server_name, source_ip=ip,
                         location_hint="body", user_agent=ua, referer=ref)
            except Exception:
                pass
            return await call_next(request)

    app.add_middleware(_Mw)

# ── hook for the reasoning-capture path (tool args + injected capture fields) ──
def scan_tool_call(tool: str, arguments: dict, capture_fields: dict, *,
                   server, source_ip=None, session_id=None):
    """
    Call this from reasoning_capture.py right after a tool call is received.
    Catches keys pasted into tool arguments (e.g. a query, a fetch URL) and into
    the injected fields (operator_instructions / context often carry secrets).
    """
    scan(arguments,      server=server, source_ip=source_ip, session_id=session_id,
         location_hint=f"tool_arg:{tool}")
    scan(capture_fields, server=server, source_ip=source_ip, session_id=session_id,
         location_hint="capture_field")

# ── OPTIONAL, disabled by default: report a leaked key for REVOCATION ─────────
def report_for_revocation(record: dict):
    """
    The one responsible outbound action: hand a captured key to the provider's
    leaked-secret / abuse channel so THEY revoke it. This does NOT authenticate
    with the key. Disabled unless ACV_CRED_REPORT=1 and you wire a real client.
    Left as a stub on purpose — implement per provider (e.g. GitHub secret-
    scanning intake, AWS abuse) and log the outcome as `credential_revocation`.
    """
    if os.environ.get("ACV_CRED_REPORT", "0") != "1":
        return
    log.info(json.dumps({"_type": "credential_revocation_todo",
                         "provider": record["provider"], "sha256": record["sha256"]}))
