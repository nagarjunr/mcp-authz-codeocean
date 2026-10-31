# Code Ocean Capsule — mcp-local-authz

This is the reproducibility capsule for mcp-local-authz: fully offline authorization for AI agents on industrial MCP servers.

## What this capsule runs

```bash
uv sync --frozen --no-cache
uv run pytest -v
```

`run` in this directory does exactly this, with output logged to `/results`. It
auto-detects the project root at runtime (checks `/code` first, since that's where
Code Ocean's git-clone import actually places this repo's contents, with a fallback
search) -- no manual file reorganizing is needed.

Expected result: **66 passed, 11 skipped**.

## Scope: 77 tests total, 66 run here, 11 skip (by design, not error)

66 tests are fully self-contained -- the policy decision engine, local CA/PKI,
policy-document signing, hash-chained audit log, FastMCP middleware enforcement,
confused-deputy privilege-relay scenarios, and token-replay scenarios. All run
entirely in-process (a locally generated CA, an in-memory FastMCP test server, a
temp-dir-backed audit log), with zero external service dependency.

Two test files -- `tests/test_ditto_retrofit.py` (5 tests) and
`tests/test_mqtt_retrofit.py` (6 tests), 11 tests combined -- each require a REAL,
live backend service: a running Eclipse Ditto stack or Eclipse Mosquitto MQTT broker,
via Docker Compose. Code Ocean's standard compute environment does not support
Docker-in-Docker on most plans, so these two files skip automatically here, the same
way they skip in any environment without a broker reachable: via their own
`DITTO_BASE_URL` / `MQTT_HOST` environment-variable guards (`pytest.mark.skipif`), not
a crash or silent omission. The run script's output makes this explicit.

These 11 tests were run for REAL against live services -- confirmed via HTTP calls to
a genuine Eclipse Ditto REST API and a genuine MQTT PUBLISH/ack round-trip -- on an
NVIDIA Jetson Orin Nano during this project's development. See the project's Evaluation
section (Section VI) for that hardware-verified result.

## To reproduce the full 77-test suite yourself (outside Code Ocean)

```bash
git clone https://github.com/nagarjunr/mcp-authz-codeocean.git
git clone https://github.com/nagarjunr/iot-mcp-servers.git   # for the real servers

# Eclipse Ditto:
cd iot-mcp-servers/eclipse-ditto && docker compose up -d
cd ../../mcp-authz-codeocean
DITTO_BASE_URL=http://localhost:8080 DITTO_USERNAME=ditto DITTO_PASSWORD=ditto \
  uv run pytest tests/test_ditto_retrofit.py -v

# Eclipse Mosquitto (mqtt):
cd ../iot-mcp-servers/mqtt && docker compose up -d mosquitto
cd ../../mcp-authz-codeocean
MQTT_HOST=localhost MQTT_PORT=1883 MQTT_USERNAME=mqtt MQTT_PASSWORD=mqtt \
  uv run pytest tests/test_mqtt_retrofit.py -v
```

## A note on how this repo relates to its source repo

This repo (`mcp-authz-codeocean`) is a code-only public mirror of a private research
repository. It exists solely because Code Ocean's Git-import feature requires a
public repository. It contains only the implementation code and tests -- see the root `README.md`.
