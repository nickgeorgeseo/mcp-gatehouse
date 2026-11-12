"""Shared test support.

``OpenGatehouse`` is the gate with its declarations made for tests that
aren't about them: in-memory clients act as a declared local caller, and a
tool that names no policy gets ``any_caller``. Tests about identity and
authorization use the real ``Gatehouse``.
"""

from __future__ import annotations

import contextlib
import functools
import socket
from collections.abc import AsyncIterator, Callable
from typing import Any

import anyio
import httpx2
import uvicorn

from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

from mcp_gatehouse import AccessTier, Caller, Gatehouse, any_caller

LOCAL = Caller(client_id="test-client", subject="tester")
LOCAL_ENTRY = {"client_id": "test-client", "subject": "tester", "issuer": None, "scopes": [], "source": "local"}

ISSUER = "https://idp.example"


class OpenGatehouse(Gatehouse):
    def __init__(self, server: Any, policy: Any = None, audit: Any = None, *, local_caller: Caller | None = LOCAL,
                 **kwargs: Any) -> None:
        super().__init__(server, policy, audit, local_caller=local_caller, **kwargs)

    def tool(self, tier: Any = AccessTier.READ, *, authorize: Any = any_caller, **kwargs: Any) -> Any:
        return super().tool(tier, authorize=authorize, **kwargs)

    def guard(self, fn: Any, name: str, tier: Any, *, authorize: Any = any_caller) -> Any:
        """The guard the gate would put around ``fn``, without registering it.

        Called directly there is no request behind it, so no local caller:
        call it inside ``signed_in(...)``.
        """
        from mcp_gatehouse.gatehouse import _build_spec

        spec = _build_spec(fn, name, tier, authorize, None, self.consistency, frozenset(), self.policy)
        return self._guard(spec)


def token(user: str, scopes: tuple[str, ...] = ("orders:read",), *, named: bool = True,
          resource: str | None = None, claims: dict[str, Any] | None = None) -> AccessToken:
    """A verified token for `user`; `named=False` is a verifier that sets no subject."""
    return AccessToken(
        token=f"secret-token-{user}",
        client_id="support-agent",
        scopes=list(scopes),
        subject=user if named else None,
        claims=({"iss": ISSUER} | (claims or {})) if named else claims,
        resource=resource,
    )


@contextlib.contextmanager
def signed_in(access_token: AccessToken):
    """What the SDK's AuthContextMiddleware does around each HTTP request."""
    reset = auth_context_var.set(AuthenticatedUser(access_token))
    try:
        yield
    finally:
        auth_context_var.reset(reset)


@contextlib.asynccontextmanager
async def http_server(make_app: Callable[[str], Any]) -> AsyncIterator[str]:
    """Serve `make_app(url)` on a port the OS picks. The socket is bound
    before the server starts and handed to it, so nothing can take the port
    in between."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}/mcp"
    server = uvicorn.Server(uvicorn.Config(make_app(url), log_level="warning"))
    try:
        with anyio.fail_after(30):
            async with anyio.create_task_group() as tg:
                tg.start_soon(functools.partial(server.serve, sockets=[sock]))
                while not server.started:
                    await anyio.sleep(0.02)
                try:
                    yield url
                finally:
                    server.should_exit = True
    finally:
        sock.close()


def bearer(presented: str) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(headers={"Authorization": f"Bearer {presented}"})
