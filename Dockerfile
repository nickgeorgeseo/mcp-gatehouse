# syntax=docker/dockerfile:1
#
# Dockerfile for Glama (https://glama.ai). Glama builds this image and connects
# to the resulting container over stdio to inspect the server's tools, score
# tool-definition quality, and run coherence checks.
#
# The image runs the bundled demo server (`mcp-gatehouse-demo`): an order-desk
# MCP server that wires three tools through the gatehouse at READ / WRITE /
# DESTRUCTIVE tiers, with honest readOnlyHint / destructiveHint annotations.
# There is no terminal in the container, so the DESTRUCTIVE tool's approval
# gate fails closed by design — the server still starts and exposes every tool.

FROM python:3.12-slim

# Don't buffer stdout/stderr — stdio is the JSON-RPC transport.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install the package from source so the release matches this commit exactly.
COPY . /app
RUN pip install .

# stdio transport: the MCP client (Glama) speaks JSON-RPC over stdin/stdout.
ENTRYPOINT ["mcp-gatehouse-demo"]
