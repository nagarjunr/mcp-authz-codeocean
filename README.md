# mcp-local-authz-code

**Code Ocean reproducibility mirror.** This is a public, code-only companion repo for
the private research repository `mcp-local-authz`, created solely because Code
Ocean's Git-import feature requires a public repository.

This repo contains ONLY the implementation code and tests.

## What this is

Local, control-plane-optional authorization for MCP servers deployed in disconnected
industrial settings (air-gapped OT networks, unreliable/absent uplink). Four
components:

- **`ca/`** -- a locally-rooted Ed25519 certificate authority for agent identity
- **`policy_engine/`** -- the declarative policy decision engine (`policy.py`),
  policy-document signing/integrity verification (`policy_signing.py`), the
  hash-chained audit log (`audit_log.py`), and the FastMCP enforcement middleware
  (`middleware.py`)
- **`retrofit/`** -- zero-source-change retrofits of the policy-engine middleware onto
  two real, independently published industrial IoT MCP servers: Eclipse Ditto and MQTT
  (vendored copies included under `retrofit/eclipse_ditto_vendor/` and
  `retrofit/mqtt_vendor/`, verbatim from the public `iot-mcp-servers` suite)
- **`tests/`** -- 77 tests total: 66 fully self-contained (policy logic, CA/PKI,
  signing, audit log, middleware, confused-deputy privilege-relay scenarios,
  token-replay scenarios), plus 11 real-instance integration tests against a live
  Eclipse Ditto stack (5 tests) and a live Eclipse Mosquitto MQTT broker (6 tests) --
  these 11 were run for real on an NVIDIA Jetson Orin Nano during development and are
  skipped automatically here without a reachable broker (not a failure -- see each
  test file's own module docstring for exact reproduction steps)

## Running the tests

```bash
uv sync
uv run pytest -v
```

Expected: `66 passed, 11 skipped` without a live Ditto/MQTT broker running.

## Code Ocean capsule

See `code_ocean/README.md` for the exact reproducibility-capsule setup, scope, and
reproduction steps.
