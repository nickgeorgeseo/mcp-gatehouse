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

from mcp_gatehouse import Ask, AuthorizationRequest, Decision, Deny

#: What the audit line says when the engine can't be reached in time.
UNAVAILABLE_REASON = "policy engine unavailable"

#: The default answer when the engine can't be reached. The reason goes to
#: the audit log; the message goes to the model, so it can tell "not now"
#: from "no" and try again later instead of giving up on the request.
UNAVAILABLE = Deny(
    UNAVAILABLE_REASON,
    message="The authorization service did not answer, so this call was not run. "
    "Nothing was changed. The call can be retried.",
)


def unavailable_decision(on_unavailable: type[Deny] | type[Ask]) -> Decision:
    """What an unreachable engine decides: ``Deny`` (the default) refuses
    the call with :data:`UNAVAILABLE`; ``Ask`` puts it to the approver
    with the reason ``"policy engine unavailable"``. Anything else is a
    mistake in the server's setup, so it raises at startup."""
    if on_unavailable is Deny:
        return UNAVAILABLE
    if on_unavailable is Ask:
        return Ask(UNAVAILABLE_REASON)
    raise ValueError(f"on_unavailable must be Deny or Ask, not {on_unavailable!r}")


class EngineError(Exception):
    """The engine was reached, but its answer can't be used. ``reason`` is
    what the audit line should say."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def post(url: str, payload: dict[str, Any], timeout: float) -> Any:
    """POST JSON, return the decoded JSON answer.

    Raises ``ConnectionError`` when the engine can't be reached in time
    (the caller turns that into its ``on_unavailable`` decision), and
    ``EngineError`` when it answers with an HTTP error or something that
    isn't JSON. That is always a denial, whatever ``on_unavailable`` says:
    the engine answered, and the answer can't be used.
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
