# Vendored copy: eclipse-ditto MCP server

`dittomcpserver.py` in this directory is a **verbatim, unmodified copy** of the
`eclipse-ditto` server from the `iot-mcp-servers` suite
(github.com/nagarjunr/iot-mcp-servers, at the commit current as of this project's
development -- see the parent project's own git history for the exact upstream state).

It is vendored here (rather than referenced as an external path or git submodule) for
one reason: this project's central claim is a **retrofit, not a rewrite** -- the
authorization middleware must attach to the server's existing tool surface without
requiring any changes to `dittomcpserver.py` itself. Vendoring a frozen copy makes that
claim independently verifiable: anyone can diff `dittomcpserver.py` here against the
upstream file and confirm zero modifications were made to add authorization.

All the actual retrofit work lives in `retrofit/ditto_retrofit.py`, which imports this
module's `mcp` object and calls `mcp.add_middleware(...)` -- see that file for the
full explanation.
