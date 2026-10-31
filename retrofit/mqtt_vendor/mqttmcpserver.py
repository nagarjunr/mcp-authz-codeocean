import base64
import collections
import logging
import os
import threading
import time
import uuid
from typing import Annotated, Any, Literal

import paho.mqtt.client as mqtt
from fastmcp import FastMCP
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from paho.mqtt.subscribeoptions import SubscribeOptions
from pydantic import Field

logger = logging.getLogger(__name__)

MQTT_HOST = os.environ["MQTT_HOST"]
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
MQTT_CLIENT_ID = os.getenv("MQTT_CLIENT_ID", "")
MQTT_KEEPALIVE = int(os.getenv("MQTT_KEEPALIVE", "60"))
MQTT_CONNECT_TIMEOUT = float(os.getenv("MQTT_CONNECT_TIMEOUT", "10.0"))

MQTT_TRANSPORT = os.getenv("MQTT_TRANSPORT", "tcp")
MQTT_WS_PATH = os.getenv("MQTT_WS_PATH", "/mqtt")

MQTT_USE_TLS = os.getenv("MQTT_USE_TLS", "false").lower() == "true"
MQTT_TLS_CA_CERTS = os.getenv("MQTT_TLS_CA_CERTS")
MQTT_TLS_CLIENT_CERT = os.getenv("MQTT_TLS_CLIENT_CERT")
MQTT_TLS_CLIENT_KEY = os.getenv("MQTT_TLS_CLIENT_KEY")
MQTT_TLS_INSECURE = os.getenv("MQTT_TLS_INSECURE", "false").lower() == "true"

MQTT_WILL_TOPIC = os.getenv("MQTT_WILL_TOPIC")
MQTT_WILL_PAYLOAD = os.getenv("MQTT_WILL_PAYLOAD", "")
MQTT_WILL_QOS = int(os.getenv("MQTT_WILL_QOS", "0"))
MQTT_WILL_RETAIN = os.getenv("MQTT_WILL_RETAIN", "false").lower() == "true"

_TOPIC_DESC = "MQTT topic to publish to (no wildcards allowed), e.g. 'sensors/room-1/temperature'."
_TOPIC_FILTER_DESC = "MQTT topic filter, may include wildcards '+' (single level) and '#' (multi level), e.g. 'sensors/+/temperature' or 'sensors/#'."
_SESSION_ID_DESC = "Session ID returned by start_subscription."


# ---------------------------------------------------------------------------
# Subscription session state
# ---------------------------------------------------------------------------


class _Session:
    def __init__(self, session_id: str, topic_filter: str, qos: int):
        self.session_id = session_id
        self.topic_filter = topic_filter
        self.qos = qos
        self.buffer: collections.deque[dict[str, Any]] = collections.deque(maxlen=10000)
        self.lock = threading.Lock()
        self.new_message_event = threading.Event()
        self.created_at = time.time()
        self.message_count = 0


_sessions: dict[str, _Session] = {}
_sessions_lock = threading.Lock()
_filter_refcount: dict[str, int] = {}


def _decode_payload(payload: bytes) -> Any:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(payload).decode("ascii")}


def _serialize_message(msg: mqtt.MQTTMessage) -> dict[str, Any]:
    result: dict[str, Any] = {
        "topic": msg.topic,
        "payload": _decode_payload(msg.payload),
        "qos": msg.qos,
        "retain": msg.retain,
    }
    props = msg.properties
    if props is not None:
        user_props = getattr(props, "UserProperty", None)
        if user_props:
            result["user_properties"] = dict(user_props) if isinstance(user_props, list) else dict([user_props])
        content_type = getattr(props, "ContentType", None)
        if content_type is not None:
            result["content_type"] = content_type
        expiry = getattr(props, "MessageExpiryInterval", None)
        if expiry is not None:
            result["message_expiry_interval"] = expiry
        response_topic = getattr(props, "ResponseTopic", None)
        if response_topic is not None:
            result["response_topic"] = response_topic
        correlation_data = getattr(props, "CorrelationData", None)
        if correlation_data is not None:
            result["correlation_data"] = base64.b64encode(correlation_data).decode("ascii")
    return result


def _dispatch_message(client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
    serialized = _serialize_message(msg)
    with _sessions_lock:
        sessions = list(_sessions.values())
    for session in sessions:
        if mqtt.topic_matches_sub(session.topic_filter, msg.topic):
            with session.lock:
                session.buffer.append(serialized)
                session.message_count += 1
            session.new_message_event.set()


def _on_connect(client: mqtt.Client, userdata: Any, flags: Any, reason_code: Any, properties: Any) -> None:
    if not reason_code.is_failure:
        logger.info(f"Connected to MQTT broker {MQTT_HOST}:{MQTT_PORT} (reason={reason_code})")
        # Re-subscribe to all active session filters. clean_start defaults to
        # "first connect only", so a broker-side reconnect after a network
        # blip would otherwise silently drop these subscriptions.
        with _sessions_lock:
            filters = list(_filter_refcount.keys())
        for topic_filter in filters:
            client.subscribe(topic_filter)
    else:
        logger.error(f"Failed to connect to MQTT broker: {reason_code}")
    _connect_result["reason_code"] = reason_code
    _connect_event.set()


_connect_event = threading.Event()
_connect_result: dict[str, Any] = {}


def _build_client() -> mqtt.Client:
    transport: Literal["tcp", "websockets"] = "websockets" if MQTT_TRANSPORT == "websockets" else "tcp"
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=MQTT_CLIENT_ID,
        protocol=mqtt.MQTTv5,
        transport=transport,
    )
    if transport == "websockets":
        client.ws_set_options(path=MQTT_WS_PATH)
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    if MQTT_USE_TLS:
        client.tls_set(
            ca_certs=MQTT_TLS_CA_CERTS,
            certfile=MQTT_TLS_CLIENT_CERT,
            keyfile=MQTT_TLS_CLIENT_KEY,
        )
        if MQTT_TLS_INSECURE:
            client.tls_insecure_set(True)
    if MQTT_WILL_TOPIC:
        client.will_set(MQTT_WILL_TOPIC, MQTT_WILL_PAYLOAD, qos=MQTT_WILL_QOS, retain=MQTT_WILL_RETAIN)

    client.on_connect = _on_connect
    client.on_message = _dispatch_message

    client.connect(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
    client.loop_start()

    if not _connect_event.wait(timeout=MQTT_CONNECT_TIMEOUT):
        client.loop_stop()
        raise RuntimeError(f"Timed out connecting to MQTT broker {MQTT_HOST}:{MQTT_PORT} after {MQTT_CONNECT_TIMEOUT}s")
    reason_code = _connect_result.get("reason_code")
    if reason_code is not None and reason_code.is_failure:
        client.loop_stop()
        raise RuntimeError(f"Failed to connect to MQTT broker {MQTT_HOST}:{MQTT_PORT}: {reason_code}")
    return client


client = _build_client()

mcp = FastMCP("mqtt")


# ---------------------------------------------------------------------------
# Connection status
# ---------------------------------------------------------------------------


@mcp.tool()
def get_connection_status() -> dict[str, Any]:
    """Report this connector's current connection to the MQTT broker.

    Returns:
        {connected, host, port, transport, protocol, client_id, active_subscriptions}
    """
    with _sessions_lock:
        active = len(_sessions)
    return {
        "connected": client.is_connected(),
        "host": MQTT_HOST,
        "port": MQTT_PORT,
        "transport": MQTT_TRANSPORT,
        "protocol": "MQTTv5",
        "client_id": client._client_id.decode("utf-8", errors="replace") if client._client_id else "(broker-assigned)",
        "active_subscriptions": active,
    }


# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------


@mcp.tool()
def publish_message(
    topic: Annotated[str, Field(description=_TOPIC_DESC)],
    payload: Annotated[str, Field(description="Message payload (UTF-8 text or JSON string).")],
    qos: Annotated[int, Field(description="Quality of service: 0 (at most once), 1 (at least once), 2 (exactly once).", ge=0, le=2)] = 0,
    retain: Annotated[bool, Field(description="If True, the broker keeps this as the topic's retained message.")] = False,
    content_type: Annotated[str | None, Field(description="MQTT5 Content-Type property, e.g. 'application/json'.")] = None,
    message_expiry_interval: Annotated[int | None, Field(description="MQTT5 seconds after which the broker may discard this message if undelivered.")] = None,
    response_topic: Annotated[str | None, Field(description="MQTT5 Response-Topic property, for request/response patterns.")] = None,
    correlation_data: Annotated[str | None, Field(description="MQTT5 Correlation-Data property (plain text; sent as UTF-8 bytes).")] = None,
    user_properties: Annotated[dict[str, str] | None, Field(description="MQTT5 arbitrary user properties (key/value pairs).")] = None,
    wait_for_ack: Annotated[bool, Field(description="For qos > 0, block until the broker acknowledges delivery.")] = True,
    ack_timeout: Annotated[float, Field(description="Seconds to wait for the ack when wait_for_ack is True.", ge=0.1, le=60.0)] = 10.0,
) -> dict[str, Any]:
    """Publish a message to an MQTT topic.

    Wraps the MQTT PUBLISH packet, including MQTT5 properties.
    """
    properties = None
    if any([content_type, message_expiry_interval is not None, response_topic, correlation_data, user_properties]):
        properties = Properties(PacketTypes.PUBLISH)
        if content_type:
            properties.ContentType = content_type
        if message_expiry_interval is not None:
            properties.MessageExpiryInterval = message_expiry_interval
        if response_topic:
            properties.ResponseTopic = response_topic
        if correlation_data:
            properties.CorrelationData = correlation_data.encode("utf-8")
        if user_properties:
            for key, value in user_properties.items():
                properties.UserProperty = (key, value)

    info = client.publish(topic, payload, qos=qos, retain=retain, properties=properties)
    if info.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"Publish to '{topic}' failed: {mqtt.error_string(info.rc)}")

    acked = qos == 0
    if qos > 0 and wait_for_ack:
        info.wait_for_publish(timeout=ack_timeout)
        acked = info.is_published()

    return {
        "topic": topic,
        "qos": qos,
        "retain": retain,
        "mid": info.mid,
        "acknowledged": acked,
    }


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------


@mcp.tool()
def start_subscription(
    topic_filter: Annotated[str, Field(description=_TOPIC_FILTER_DESC)],
    qos: Annotated[int, Field(description="Maximum QoS to request for this subscription.", ge=0, le=2)] = 0,
    no_local: Annotated[bool, Field(description="MQTT5: don't receive messages published by this same connection.")] = False,
    retain_as_published: Annotated[bool, Field(description="MQTT5: keep the original retain flag on received messages instead of always False.")] = False,
) -> dict[str, Any]:
    """Start receiving messages matching a topic filter.

    Creates a session that buffers incoming messages; call get_messages(session_id)
    to drain them, and stop_subscription(session_id) when done.

    Returns:
        {session_id, topic_filter, qos}
    """
    session_id = uuid.uuid4().hex
    session = _Session(session_id, topic_filter, qos)

    with _sessions_lock:
        _sessions[session_id] = session
        _filter_refcount[topic_filter] = _filter_refcount.get(topic_filter, 0) + 1
        is_first_for_filter = _filter_refcount[topic_filter] == 1

    if is_first_for_filter:
        options = SubscribeOptions(qos=qos, noLocal=no_local, retainAsPublished=retain_as_published)
        result, _mid = client.subscribe(topic_filter, options=options)
        if result != mqtt.MQTT_ERR_SUCCESS:
            with _sessions_lock:
                del _sessions[session_id]
                _filter_refcount[topic_filter] -= 1
            raise RuntimeError(f"Subscribe to '{topic_filter}' failed: {mqtt.error_string(result)}")

    return {"session_id": session_id, "topic_filter": topic_filter, "qos": qos}


@mcp.tool()
def get_messages(
    session_id: Annotated[str, Field(description=_SESSION_ID_DESC)],
    max_messages: Annotated[int, Field(description="Maximum number of buffered messages to return.", ge=1, le=1000)] = 100,
    timeout_seconds: Annotated[float, Field(description="If no messages are buffered, wait up to this long for one to arrive.", ge=0.0, le=60.0)] = 0.0,
) -> dict[str, Any]:
    """Drain buffered messages received by a subscription session.

    Returns:
        {messages: [...], count, buffered_remaining}
    """
    session = _sessions.get(session_id)
    if session is None:
        raise ValueError(f"No such subscription session: '{session_id}'")

    def _drain(limit: int) -> list[dict[str, Any]]:
        with session.lock:
            n = min(limit, len(session.buffer))
            return [session.buffer.popleft() for _ in range(n)]

    messages = _drain(max_messages)

    if not messages and timeout_seconds > 0:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            session.new_message_event.wait(timeout=remaining)
            session.new_message_event.clear()
            messages = _drain(max_messages)
            if messages:
                break

    with session.lock:
        remaining_buffered = len(session.buffer)
    return {"messages": messages, "count": len(messages), "buffered_remaining": remaining_buffered}


@mcp.tool()
def stop_subscription(session_id: Annotated[str, Field(description=_SESSION_ID_DESC)]) -> dict[str, Any]:
    """Stop a subscription session and discard its buffered messages.

    Unsubscribes from the broker only if no other active session shares the
    same topic filter.
    """
    with _sessions_lock:
        session = _sessions.pop(session_id, None)
        if session is None:
            raise ValueError(f"No such subscription session: '{session_id}'")
        _filter_refcount[session.topic_filter] -= 1
        should_unsubscribe = _filter_refcount[session.topic_filter] <= 0
        if should_unsubscribe:
            del _filter_refcount[session.topic_filter]

    if should_unsubscribe:
        client.unsubscribe(session.topic_filter)

    return {"session_id": session_id, "topic_filter": session.topic_filter, "stopped": True}


@mcp.tool()
def list_subscriptions() -> dict[str, Any]:
    """List all active subscription sessions on this connector.

    Returns:
        {sessions: [{session_id, topic_filter, qos, buffered_count, message_count, created_at}]}
    """
    with _sessions_lock:
        sessions = list(_sessions.values())
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "topic_filter": s.topic_filter,
                "qos": s.qos,
                "buffered_count": len(s.buffer),
                "message_count": s.message_count,
                "created_at": s.created_at,
            }
            for s in sessions
        ]
    }


# ---------------------------------------------------------------------------
# Topic discovery (via retained messages)
# ---------------------------------------------------------------------------


@mcp.tool()
def discover_topics(
    topic_filter: Annotated[str, Field(description=_TOPIC_FILTER_DESC)] = "#",
    duration_seconds: Annotated[float, Field(description="How long to listen for retained messages.", ge=0.5, le=30.0)] = 5.0,
    max_topics: Annotated[int, Field(description="Stop early once this many distinct topics are seen.", ge=1, le=1000)] = 100,
) -> dict[str, Any]:
    """Discover live topics by briefly subscribing and collecting retained messages.

    MQTT has no built-in "list topics" operation; this approximates one using
    the standard mechanism (retained messages, delivered immediately on
    subscribe). Topics with no retained message won't be discovered this way
    unless a matching publish happens to occur during the window.

    Returns:
        {topics: [{topic, payload, qos, retain}], count, stopped_reason}
    """
    result = start_subscription(topic_filter, qos=0)
    session_id = result["session_id"]
    seen: dict[str, dict[str, Any]] = {}
    stopped_reason = "timeout"
    deadline = time.monotonic() + duration_seconds
    try:
        while time.monotonic() < deadline and len(seen) < max_topics:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            batch = get_messages(session_id, max_messages=max_topics, timeout_seconds=remaining)
            for msg in batch["messages"]:
                seen[msg["topic"]] = msg
                if len(seen) >= max_topics:
                    stopped_reason = "max_topics"
                    break
            if not batch["messages"]:
                break
    finally:
        stop_subscription(session_id)

    return {"topics": list(seen.values()), "count": len(seen), "stopped_reason": stopped_reason}


_Transport = Literal["stdio", "http", "sse", "streamable-http"]


def _get_mcp_init_vars() -> tuple[_Transport, str, int]:
    """Get MCP initialization variables from environment configuration.

    Returns:
        tuple[_Transport, str, int]: transport, host, port.
    """
    raw_transport = os.getenv("TRANSPORT") or "stdio"
    if raw_transport in ["stdio", "<TRANSPORT>", "", "-", "null"]:
        logger.info("MCP init: transport=stdio")
        return ("stdio", "", 0)

    transport: _Transport
    if raw_transport == "http":
        transport = "http"
    elif raw_transport == "sse":
        transport = "sse"
    elif raw_transport == "streamable-http":
        transport = "streamable-http"
    else:
        raise ValueError(
            f"Invalid TRANSPORT env variable: '{raw_transport}' - must be one of stdio, http, sse, streamable-http"
        )

    host = os.getenv("HOST") or "127.0.0.1"
    port_str = os.getenv("HOST_PORT") or "8000"
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Invalid HOST_PORT env variable: '{port_str}' - must be a valid integer")
    logger.info(f"MCP init: transport={transport}, host={host}, port={port}")
    return (transport, host, port)


def main() -> None:
    transport, host, port = _get_mcp_init_vars()
    try:
        if transport == "stdio":
            mcp.run()
        else:
            mcp.run(transport=transport, transport_options={"host": host, "port": port})
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
