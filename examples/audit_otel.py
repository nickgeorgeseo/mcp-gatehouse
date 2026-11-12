"""Forward the audit log to OpenTelemetry logs.

The gate hands every audit record to a sink. This one turns each record
into an OpenTelemetry log record, so the trail lands wherever your logs
pipeline sends them (an OTLP collector, a vendor backend), next to the
server's traces. Nothing about the record changes: the body is the same
JSON object `JsonlSink` would have written as one line, and the fields
that are worth filtering on (tool, tier, outcome, authz, caller) are
repeated as attributes.

Needs `pip install opentelemetry-sdk`, and an exporter for your backend,
such as `opentelemetry-exporter-otlp`. The library itself depends on
nothing but the `mcp` SDK; this file is the only place OpenTelemetry is
imported.

Run it to see the records on stdout, as the console exporter prints them:

    python examples/audit_otel.py
"""

from __future__ import annotations

import datetime
import json
from typing import Any

from opentelemetry._logs import SeverityNumber, set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import ConsoleLogRecordExporter, SimpleLogRecordProcessor
from opentelemetry.sdk.resources import Resource

from mcp_gatehouse import AuditLog, AuditSink

# What the record's outcome means to someone reading a log viewer.
SEVERITY = {
    "ok": SeverityNumber.INFO,
    "pending": SeverityNumber.INFO,
    "denied": SeverityNumber.WARN,
    "conflict": SeverityNumber.WARN,
    "cancelled": SeverityNumber.WARN,
    "error": SeverityNumber.ERROR,
}

# Fields worth an attribute of their own, so a viewer can filter on them
# without parsing the body. Everything else stays in the body only.
INDEXED = ("tool", "tier", "outcome", "reason", "authz", "consistency", "withheld")


class OpenTelemetrySink:
    """An :class:`AuditSink` that emits one OpenTelemetry log record per
    audit record.

    A record the exporter can't deliver is the exporter's problem to
    retry or drop by its own rules; one this sink can't even emit raises,
    and the gate then writes that line to stderr with ``sink_error`` and
    goes on, so nothing is lost without a trace.
    """

    def __init__(self, provider: LoggerProvider, name: str = "mcp_gatehouse") -> None:
        self._logger = provider.get_logger(name)

    def write(self, record: dict[str, Any]) -> None:
        attributes: dict[str, Any] = {f"gatehouse.{k}": record[k] for k in INDEXED if k in record}
        caller = record.get("caller")
        if caller:
            attributes["enduser.id"] = caller.get("subject") or ""
            attributes["gatehouse.caller.client_id"] = caller["client_id"]
            if caller.get("source") == "local":
                attributes["gatehouse.caller.source"] = "local"
        self._logger.emit(
            timestamp=int(datetime.datetime.fromisoformat(record["ts"]).timestamp() * 1e9),
            # The whole record, as the JSONL sink would have written it, so
            # a reader can validate it against docs/audit-line.schema.json.
            body=json.dumps(record, ensure_ascii=True, default=str),
            severity_number=SEVERITY.get(record.get("outcome", ""), SeverityNumber.INFO),
            severity_text=str(record.get("outcome", "")),
            attributes=attributes,
            event_name="mcp_gatehouse.audit",
        )


def audit_log(provider: LoggerProvider) -> AuditLog:
    """The audit log for a `Gatehouse(..., audit=audit_log(provider))`."""
    sink: AuditSink = OpenTelemetrySink(provider)
    return AuditLog(sink=sink)


if __name__ == "__main__":
    # Swap the console exporter for OTLPLogExporter(endpoint=...) from
    # opentelemetry-exporter-otlp to ship them to a collector.
    provider = LoggerProvider(resource=Resource.create({"service.name": "order-desk"}))
    provider.add_log_record_processor(SimpleLogRecordProcessor(ConsoleLogRecordExporter()))
    set_logger_provider(provider)

    log = audit_log(provider)
    log.record(
        tool="cancel_order", tier="destructive", outcome="denied", reason="policy: someone else's order",
        arguments={"order_id": "4420"},
        caller={"client_id": "local", "subject": "alice", "issuer": None, "scopes": [], "source": "local"},
        authz="deny", resources={"order": {"order_id": "4420"}}, consistency="conditional",
    )
    provider.shutdown()
