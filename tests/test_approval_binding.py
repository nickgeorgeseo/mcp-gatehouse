"""An approval binds to the record's state: any field that changes while a
person decides voids it, whatever its type."""
from __future__ import annotations

import enum
import io
import uuid
from typing import Annotated

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from mcp_gatehouse import AccessTier, AcceptRace, AuditLog, Load, Policy
from _support import OpenGatehouse as Gatehouse

pytestmark = pytest.mark.anyio


class Status(enum.Enum):
    PACKED = "packed"
    PICKING = "picking"


class Order(BaseModel):
    id: str
    status: Status
    ref: uuid.UUID
    total: float


def run(change):
    db = {"4417": Order(id="4417", status=Status.PACKED, ref=uuid.UUID(int=1), total=812.0)}
    ran, seen = [], []

    def approver(request):
        seen.append(request.resources)
        change(db)  # the record changes while the person decides
        return True

    mcp = MCPServer("binding")
    stream = io.StringIO()
    gh = Gatehouse(mcp, policy=Policy(approver=approver), audit=AuditLog(stream=stream),
                   consistency=AcceptRace("test"))

    def load(order_id: str) -> Order:
        return db[order_id].model_copy()

    the_order = Load(load)

    @gh.tool(tier=AccessTier.DESTRUCTIVE)
    def cancel_order(order_id: str, order: Annotated[Order, the_order]) -> str:
        ran.append(order.status)
        return "cancelled"

    return mcp, ran, seen, stream


async def _call(mcp):
    async with Client(mcp) as client:
        return await client.call_tool("cancel_order", {"order_id": "4417"})


async def test_a_float_change_voids_the_approval():
    mcp, ran, seen, _ = run(lambda db: db.__setitem__("4417", db["4417"].model_copy(update={"total": 99999.0})))
    r = await _call(mcp)
    assert ran == [] and "changed" in r.content[0].text, r.content[0].text


async def test_an_enum_field_change_voids_the_approval():
    mcp, ran, seen, stream = run(lambda db: db.__setitem__("4417", db["4417"].model_copy(update={"status": Status.PICKING})))
    await _call(mcp)
    assert ran == [], f"ran on a record whose status changed after approval; approver saw {seen}"


async def test_a_uuid_field_change_voids_the_approval():
    mcp, ran, seen, _ = run(lambda db: db.__setitem__("4417", db["4417"].model_copy(update={"ref": uuid.UUID(int=2)})))
    await _call(mcp)
    assert ran == [], f"ran on a record whose ref changed after approval; approver saw {seen}"


class Blob(BaseModel):
    id: str
    payload: bytes


def blob_server(fingerprint=None):
    db = {"1": Blob(id="1", payload=b"a")}
    ran = []
    mcp = MCPServer("binding")
    gh = Gatehouse(mcp, policy=Policy(approver=lambda request: True), audit=AuditLog(stream=io.StringIO()),
                   consistency=AcceptRace("test"))
    the_blob = Load(lambda blob_id: db[blob_id], fingerprint=fingerprint)

    @gh.tool(tier=AccessTier.DESTRUCTIVE)
    def wipe(blob_id: str, blob: Annotated[Blob, the_blob]) -> str:
        ran.append(blob.id)
        return "wiped"

    return mcp, ran


async def test_a_record_with_a_field_the_gate_cant_see_needs_a_fingerprint():
    """bytes is shown only by its type, so a change to it would go unseen:
    without fingerprint= the gate can't bind the approval, and refuses."""
    mcp, ran = blob_server()
    async with Client(mcp) as client:
        result = await client.call_tool("wipe", {"blob_id": "1"})
    assert ran == [] and result.is_error


async def test_a_fingerprint_lets_that_record_be_approved():
    mcp, ran = blob_server(fingerprint=lambda blob: blob.payload.hex())
    async with Client(mcp) as client:
        await client.call_tool("wipe", {"blob_id": "1"})
    assert ran == ["1"]
