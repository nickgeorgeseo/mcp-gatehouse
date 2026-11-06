"""Shared by policy_opa.py and policy_cerbos.py: one POST to a policy
engine, standard library only, and the record as attributes.

Not part of the library. The gate's policies are plain callables; these
helpers only keep the two examples from repeating each other.
"""

from __future__ import annotations

import dataclasses
import http.client
import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

from mcp_gatehouse import AuthorizationRequest, Deny

UNAVAILABLE = Deny("policy engine unavailable")


class EngineError(Exception):
    """The engine was reached, but its answer can't be used. ``reason`` is
    what the audit line should say."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def post(url: str, payload: dict[str, Any], timeout: float) -> Any:
    """POST JSON, return the decoded JSON answer.

    Raises ``ConnectionError`` when the engine can't be reached in time
    (the caller turns that into ``Deny("policy engine unavailable")``), and
    ``EngineError`` when it answers with an HTTP error or something that
    isn't JSON. Either way the call is denied: a policy that can't decide
    has decided no.
    """
    body = json.dumps(payload, default=str).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise EngineError(f"policy engine error: HTTP {exc.code}") from None
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
        raise ConnectionError(str(exc)) from None
    try:
        return json.loads(raw)
    except ValueError:
        raise EngineError("policy engine returned an unreadable answer") from None


def attributes(record: Any) -> dict[str, Any]:
    """The loaded record as plain JSON-shaped attributes for the engine."""
    if isinstance(record, Mapping):
        return dict(record)
    if dataclasses.is_dataclass(record) and not isinstance(record, type):
        return dataclasses.asdict(record)
    dump = getattr(record, "model_dump", None)  # pydantic
    if callable(dump):
        return dump(mode="json")
    raise TypeError(f"can't send a {type(record).__name__} to the policy engine as attributes")


def subject_of(request: AuthorizationRequest) -> dict[str, Any]:
    """The caller, as the engine should see it. Never the token."""
    caller = request.caller
    return {
        "client_id": caller.client_id,
        "subject": caller.subject,
        "issuer": caller.issuer,
        "scopes": list(caller.scopes),
    }


def record_of(request: AuthorizationRequest) -> tuple[str, Any]:
    """The one record this request is about: the item being filtered, or
    the tool's single ``Load`` parameter."""
    if request.action == "read":
        return "item", request.resource
    if len(request.resources) != 1:
        raise TypeError("these examples decide on one loaded record; this tool has " f"{len(request.resources)}")
    ((name, record),) = request.resources.items()
    return name, record
