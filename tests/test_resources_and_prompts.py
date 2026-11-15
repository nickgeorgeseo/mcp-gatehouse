"""Resources, prompts and completions on a gated server.

They are other ways to the data behind the tools, with no policy: a
resource template reads the record a tool would, and a completion suggests
values without knowing who asks. The gate refuses all three around it, and
lets through only resources and prompts registered as open, which any
verified caller may read.
"""

from __future__ import annotations

import pytest
from mcp import Client, MCPError
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.resources import TextResource

from mcp_gatehouse import AccessTier, Deny, Gatehouse, any_caller

from _support import OpenGatehouse

pytestmark = pytest.mark.anyio


# --- refused around the gate -------------------------------------------------


def test_a_resource_template_is_refused():
    mcp = MCPServer("t")
    Gatehouse(mcp)
    with pytest.raises(TypeError, match="open_resource"):
        @mcp.resource("orders://{order_id}")
        def order(order_id: str) -> str:
            return order_id


def test_a_static_resource_is_refused():
    mcp = MCPServer("t")
    Gatehouse(mcp)
    with pytest.raises(TypeError, match="open_resource"):
        mcp.add_resource(TextResource(uri="docs://readme", text="hi"))
    with pytest.raises(TypeError, match="open_resource"):
        mcp._resource_manager.add_resource(TextResource(uri="docs://readme", text="hi"))


def test_a_prompt_is_refused():
    mcp = MCPServer("t")
    Gatehouse(mcp)
    with pytest.raises(TypeError, match="open_prompt"):
        @mcp.prompt()
        def summarize(order_id: str) -> str:
            return order_id


def test_a_completion_is_refused():
    mcp = MCPServer("t")
    Gatehouse(mcp)
    with pytest.raises(TypeError, match="completion"):
        mcp.completion()


@pytest.mark.parametrize("what", ["resource", "template", "prompt", "completion"])
def test_a_server_that_already_has_one_is_refused(what):
    mcp = MCPServer("t")
    if what == "resource":
        mcp.add_resource(TextResource(uri="docs://readme", text="hi"))
    elif what == "template":
        mcp.resource("orders://{order_id}", name="order")(lambda order_id: order_id)
    elif what == "prompt":
        mcp.prompt(name="p")(lambda: "hi")
    else:
        @mcp.completion()
        async def complete(ref, argument, context):
            return None
    with pytest.raises(ValueError, match="outside the gate"):
        Gatehouse(mcp)


async def test_the_bypass_is_closed():
    """The case that found it: a tool that denies everyone beside a
    resource that served the same record to anyone."""
    mcp = MCPServer("t")
    gk = Gatehouse(mcp)

    @gk.tool(tier=AccessTier.READ, authorize=lambda request: Deny("never"))
    def read_order(order_id: str) -> str:
        return "secret"

    with pytest.raises(TypeError):
        mcp.resource("orders://{order_id}", name="order")(lambda order_id: "secret")
    async with Client(mcp) as client:
        assert (await client.list_resource_templates()).resource_templates == []


# --- open resources and prompts ----------------------------------------------


def open_server(local: bool = True) -> MCPServer:
    mcp = MCPServer("t")
    gk = OpenGatehouse(mcp) if local else Gatehouse(mcp)

    @gk.open_resource("docs://pricing", mime_type="text/plain")
    def pricing() -> str:
        return "standard: 10/month"

    @gk.open_prompt(name="triage")
    def triage(topic: str) -> str:
        return f"Triage this: {topic}"

    @gk.tool(authorize=any_caller)
    def ping() -> str:
        return "pong"

    return mcp


async def test_an_open_resource_and_prompt_serve_a_verified_caller():
    async with Client(open_server()) as client:
        read = await client.read_resource("docs://pricing")
        assert read.contents[0].text == "standard: 10/month"
        prompt = await client.get_prompt("triage", {"topic": "refund"})
        assert "refund" in prompt.messages[0].content.text


async def test_an_open_resource_and_prompt_refuse_a_request_with_no_caller():
    async with Client(open_server(local=False)) as client:
        with pytest.raises(MCPError, match="verified caller"):
            await client.read_resource("docs://pricing")
        with pytest.raises(MCPError, match="verified caller"):
            await client.get_prompt("triage", {"topic": "refund"})


async def test_reading_from_code_with_no_request_is_refused():
    mcp = open_server()
    with pytest.raises(MCPError, match="verified caller"):
        await mcp.read_resource("docs://pricing")


def test_open_resource_needs_its_uri():
    gk = Gatehouse(MCPServer("t"))
    with pytest.raises(TypeError, match="URI"):
        @gk.open_resource
        def pricing() -> str:
            return ""
