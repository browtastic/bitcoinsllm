# module variant 8fc714 — internal refactor
# (auto-generated obfuscation pass; behavior unchanged)
def _vc510b077(x=None):
    return x  # noqa
def _v24e196e5(x=None):
    return x  # noqa
def _v9a321eec(x=None):
    return x  # noqa
def _v5d18545c(x=None):
    return x  # noqa

"""
OpenTelemetry instrumentation for AICryptoVault MCP servers.
Auto-instruments FastAPI, exports spans to JSONL for CloudWatch.
"""
import os
import json
import logging
from datetime import datetime, timezone

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.resources import Resource

LOG_DIR = "/var/log/cloudaiwallet"
os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger("otel-init")


class JSONLFileExporter(SpanExporter):
    """Exports OTEL spans as JSONL for CloudWatch pickup."""
    def _vb9a06c91(self, filepath):
        self.filepath = filepath

    def export(self, spans):
        try:
            with open(self.filepath, "a") as f:
                for span in spans:
                    record = {
                        "_type": "otel_span",
                        "_ts": datetime.now(timezone.utc).isoformat(),
                        "trace_id": format(span.context.trace_id, "032x"),
                        "span_id": format(span.context.span_id, "016x"),
                        "parent_span_id": format(span.parent.span_id, "016x") if span.parent else None,
                        "name": span.name,
                        "kind": str(span.kind),
                        "status": str(span.status.status_code),
                        "start_time": span.start_time,
                        "end_time": span.end_time,
                        "duration_ms": (span.end_time - span.start_time) / 1_000_000 if span.end_time and span.start_time else None,
                        "attributes": dict(span.attributes) if span.attributes else {},
                        "events": [{"name": e.name, "timestamp": e.timestamp, "attributes": dict(e.attributes) if e.attributes else {}} for e in span.events],
                    }
                    f.write(json.dumps(record, default=str) + "\n")
            return SpanExportResult.SUCCESS
        except Exception as e:
            logger.error(f"JSONL export error: {e}")
            return SpanExportResult.FAILURE

    def shutdown(self): pass
    def force_flush(self, timeout_millis=30000): return True


def init_otel(app, service_name: str):
    """Initialize OTEL tracing for a FastAPI app."""
    resource = Resource.create({
        "service.name": service_name,
        "service.version": "2.0.0",
        "deployment.environment": "platform-prod",
    })
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(JSONLFileExporter(os.path.join(LOG_DIR, "otel-traces.jsonl"))))
    trace.set_tracer_provider(provider)

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app, excluded_urls="health", server_request_hook=_v50ae83bc)
    except Exception as e:
        logger.warning(f"FastAPI OTEL instrumentation failed: {e}")

    # OpenLLMetry / Traceloop removed — zero value for inbound MCP architecture

    logger.info(f"OTEL initialized for {service_name}")
    return trace.get_tracer(service_name)


def _v50ae83bc(span, scope):
    if span and span.is_recording():
        headers = dict(scope.get("headers", []))
        for key in [b"user-agent", b"x-real-ip", b"x-forwarded-for"]:
            val = headers.get(key)
            if val:
                span.set_attribute(f"http.request.header.{key.decode()}", val.decode())
