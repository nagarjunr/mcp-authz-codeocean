# Code Ocean environment for the mcp-local-authz reproducibility capsule.
#
# Base: Python 3.11 with uv, matching this project's actual pinned toolchain
# (pyproject.toml). Standard, no Docker-in-Docker or privileged mode required --
# unlike the iot-mcp-servers capsule, this project's core test suite (66 of 77
# tests) is fully self-contained: it uses in-process fake FastMCP servers, a locally
# generated CA, and a temp-dir-backed audit log, with no external service dependency
# at all.
#
# SCOPE NOTE (mirrors the reasoning in the Code Ocean Dockerfile): this repo
# also has two real-instance integration test files --
# tests/test_ditto_retrofit.py (needs a live Eclipse Ditto stack via docker-compose)
# and tests/test_mqtt_retrofit.py (needs a live Eclipse Mosquitto broker) -- that
# were run for real on an NVIDIA Jetson Orin Nano during this project's own
# development (see the project's evaluation notes and STRESS_TEST.md), NOT inside this
# capsule. Code Ocean's standard compute environment does not support
# Docker-in-Docker on most plans, and reproducing a Jetson/aarch64 hardware
# environment inside an x86 cloud capsule would misrepresent what was actually
# tested. Those two test files are included in this capsule's source tree for
# transparency and are SKIPPED automatically (via their own DITTO_BASE_URL /
# MQTT_HOST environment-variable guards) when no live broker is reachable --
# exactly the same skip behavior used during local (non-Jetson) development. The
# capsule's run script below runs the full pytest suite; the skip counts in its
# output make this scoping explicit and visible, not hidden.

FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv: this project's actual dependency/runner tool (see pyproject.toml)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /code
