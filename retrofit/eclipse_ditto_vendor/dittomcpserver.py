import json
import logging
import os
import time
from typing import Annotated, Any, Literal

import httpx
from fastmcp import FastMCP
from pydantic import Field

logger = logging.getLogger(__name__)

DITTO_BASE_URL = os.environ["DITTO_BASE_URL"].rstrip("/")
DITTO_USERNAME = os.getenv("DITTO_USERNAME")
DITTO_PASSWORD = os.getenv("DITTO_PASSWORD")
DITTO_BEARER_TOKEN = os.getenv("DITTO_BEARER_TOKEN")

# Ditto's DevOps HTTP API (log levels, cluster config, piggyback commands) and the
# Connections API both sit behind a separate "devops" Basic-auth realm on the
# gateway itself, independent of the policy-based auth used for things/policies.
DITTO_DEVOPS_USERNAME = os.getenv("DITTO_DEVOPS_USERNAME")
DITTO_DEVOPS_PASSWORD = os.getenv("DITTO_DEVOPS_PASSWORD")


def _build_client() -> httpx.Client:
    headers: dict[str, str] = {}
    auth: tuple[str, str] | None = None
    if DITTO_BEARER_TOKEN:
        headers["Authorization"] = f"Bearer {DITTO_BEARER_TOKEN}"
    elif DITTO_USERNAME and DITTO_PASSWORD:
        auth = (DITTO_USERNAME, DITTO_PASSWORD)
    return httpx.Client(base_url=DITTO_BASE_URL, headers=headers, auth=auth, timeout=30.0)


def _build_devops_client() -> httpx.Client:
    auth: tuple[str, str] | None = None
    if DITTO_DEVOPS_USERNAME and DITTO_DEVOPS_PASSWORD:
        auth = (DITTO_DEVOPS_USERNAME, DITTO_DEVOPS_PASSWORD)
    return httpx.Client(base_url=DITTO_BASE_URL, auth=auth, timeout=30.0)


client = _build_client()
devops_client = _build_devops_client()

mcp = FastMCP("eclipse-ditto")

# ---------------------------------------------------------------------------
# Shared parameter descriptions and helpers
# ---------------------------------------------------------------------------

_THING_ID_DESC = "Ditto thing ID in the form 'namespace:name' (e.g. 'org.eclipse.ditto:my-thing')."
_POLICY_ID_DESC = "Ditto policy ID in the form 'namespace:name'."
_FEATURE_ID_DESC = "Feature ID within the thing (e.g. 'temperature')."
_CONNECTION_ID_DESC = "Ditto connection ID."
_JSON_POINTER_DESC = (
    "Optional RFC-6901 JSON pointer path within the resource (e.g. 'configuration/brewingTemp'). "
    "Omit to target the whole resource."
)
_CONFIRM_DESC = "Must be explicitly set to True to perform this delete. Safety gate against accidental destructive calls."
_OVERWRITE_DESC = "If False (default), fails if the resource already exists. Set True to replace it."
_FIELDS_DESC = "Optional list of field selectors to project the response (e.g. ['thingId', 'attributes'])."


def _sub_path(base: str, path: str | None) -> str:
    return base if not path else f"{base}/{path}"


def _fields_param(fields: list[str] | None) -> dict[str, Any]:
    return {"fields": ",".join(fields)} if fields else {}


def _raise_for_status(resp: httpx.Response, context: str) -> None:
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"{context} ({e.response.status_code}): {e.response.text}") from e


def _require_confirm(confirm: bool, action: str) -> None:
    if not confirm:
        raise ValueError(f"Refusing to {action} without confirm=True.")


def _create_or_replace(http_client: httpx.Client, path: str, body: Any, overwrite: bool, context: str) -> httpx.Response:
    headers = {} if overwrite else {"If-None-Match": "*"}
    try:
        resp = http_client.put(path, json=body, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 412 and not overwrite:
            raise RuntimeError(f"{context} already exists (pass overwrite=True to replace it).") from e
        raise RuntimeError(f"{context} failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"{context} request failed: {e}") from e
    return resp


def _get_or_empty(http_client: httpx.Client, path: str, params: dict[str, Any], context: str) -> Any:
    try:
        resp = http_client.get(path, params=params)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {}
        raise RuntimeError(f"{context} ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"{context} request failed: {e}") from e
    return resp.json()


def _delete(http_client: httpx.Client, path: str, context: str) -> dict[str, Any]:
    try:
        http_client.delete(path).raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"{context} ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"{context} request failed: {e}") from e
    return {"deleted": True}


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


# ---------------------------------------------------------------------------
# Things: search, bulk read, CRUD
# ---------------------------------------------------------------------------


@mcp.tool()
def list_things(
    namespaces: Annotated[
        list[str] | None,
        Field(description="Restrict the search to these namespaces (e.g. ['org.eclipse.ditto']). Omit to search all."),
    ] = None,
    filter: Annotated[
        str | None,
        Field(
            description=(
                "Ditto RQL filter expression, e.g. eq(attributes/location,\"lab-1\") or "
                "gt(features/temperature/properties/value,20)."
            )
        ),
    ] = None,
    fields: Annotated[list[str] | None, Field(description=_FIELDS_DESC)] = None,
    limit: Annotated[int, Field(description="Maximum number of things to return.", ge=1, le=200)] = 25,
) -> dict[str, Any]:
    """Search/list digital twins (things) registered in Ditto.

    Wraps GET /api/2/search/things.

    Returns:
        {"items": [...], "count": int}
    """
    params: dict[str, Any] = {"option": f"limit(0,{limit})", **_fields_param(fields)}
    if namespaces:
        params["namespaces"] = ",".join(namespaces)
    if filter:
        params["filter"] = filter

    try:
        resp = client.get("/api/2/search/things", params=params)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ditto search failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Ditto search request failed: {e}") from e

    items = resp.json().get("items", [])
    return {"items": items, "count": len(items)}


@mcp.tool()
def count_things(
    namespaces: Annotated[list[str] | None, Field(description="Restrict the count to these namespaces.")] = None,
    filter: Annotated[str | None, Field(description="Ditto RQL filter expression.")] = None,
) -> int:
    """Count things matching a search filter, without fetching them.

    Wraps GET /api/2/search/things/count.
    """
    params: dict[str, Any] = {}
    if namespaces:
        params["namespaces"] = ",".join(namespaces)
    if filter:
        params["filter"] = filter
    try:
        resp = client.get("/api/2/search/things/count", params=params)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ditto count failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Ditto count request failed: {e}") from e
    return int(resp.text)


@mcp.tool()
def get_things(
    thing_ids: Annotated[list[str], Field(description="Thing IDs to fetch in a single request.")],
    fields: Annotated[list[str] | None, Field(description=_FIELDS_DESC)] = None,
) -> list[dict[str, Any]]:
    """Bulk-fetch multiple things by ID in one request.

    Wraps GET /api/2/things?ids=...
    """
    params: dict[str, Any] = {"ids": ",".join(thing_ids), **_fields_param(fields)}
    try:
        resp = client.get("/api/2/things", params=params)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch things ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for things failed: {e}") from e
    result: list[dict[str, Any]] = resp.json()
    return result


@mcp.tool()
def get_thing(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    fields: Annotated[list[str] | None, Field(description=_FIELDS_DESC)] = None,
) -> dict[str, Any]:
    """Fetch the full digital twin (attributes and features) for a thing.

    Wraps GET /api/2/things/{thingId}.
    """
    try:
        resp = client.get(f"/api/2/things/{thing_id}", params=_fields_param(fields))
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch thing '{thing_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for thing '{thing_id}' failed: {e}") from e
    return dict(resp.json())


@mcp.tool()
def put_thing(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    thing: Annotated[dict[str, Any], Field(description="Full thing JSON (attributes, features, definition, policyId).")],
    overwrite: Annotated[bool, Field(description=_OVERWRITE_DESC)] = False,
) -> dict[str, Any]:
    """Create a new thing, or replace an existing one (with overwrite=True).

    Wraps PUT /api/2/things/{thingId}. Uses If-None-Match to make the
    create-only (overwrite=False) path race-free rather than check-then-set.
    """
    resp = _create_or_replace(client, f"/api/2/things/{thing_id}", thing, overwrite, f"Thing '{thing_id}'")
    return dict(resp.json()) if resp.content else {"thingId": thing_id, "updated": True}


@mcp.tool()
def patch_thing(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    patch: Annotated[
        dict[str, Any],
        Field(description="RFC-7396 JSON Merge Patch document. A null value deletes that key from the thing."),
    ],
) -> dict[str, Any]:
    """Partially update a thing (creates it if it doesn't exist yet).

    Wraps PATCH /api/2/things/{thingId} with Content-Type: application/merge-patch+json.
    """
    try:
        resp = client.patch(
            f"/api/2/things/{thing_id}",
            content=json.dumps(patch),
            headers={"Content-Type": "application/merge-patch+json"},
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to patch thing '{thing_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Patch request for thing '{thing_id}' failed: {e}") from e
    return dict(resp.json()) if resp.content else {"thingId": thing_id, "patched": True}


@mcp.tool()
def delete_thing(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Delete a thing. Wraps DELETE /api/2/things/{thingId}. Irreversible."""
    _require_confirm(confirm, f"delete thing '{thing_id}'")
    return _delete(client, f"/api/2/things/{thing_id}", f"Failed to delete thing '{thing_id}'")


@mcp.tool()
def get_thing_policy_id(thing_id: Annotated[str, Field(description=_THING_ID_DESC)]) -> str:
    """Get the policy ID controlling access to a thing. Wraps GET /things/{thingId}/policyId."""
    try:
        resp = client.get(f"/api/2/things/{thing_id}/policyId")
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch policyId for '{thing_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for policyId of '{thing_id}' failed: {e}") from e
    return str(resp.json())


@mcp.tool()
def set_thing_policy_id(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    policy_id: Annotated[str, Field(description="Policy ID to attach to this thing.")],
) -> dict[str, Any]:
    """Repoint a thing at a different policy. Wraps PUT /things/{thingId}/policyId."""
    try:
        resp = client.put(f"/api/2/things/{thing_id}/policyId", json=policy_id)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to set policyId for '{thing_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request to set policyId of '{thing_id}' failed: {e}") from e
    return {"thingId": thing_id, "policyId": policy_id}


@mcp.tool()
def get_thing_definition(thing_id: Annotated[str, Field(description=_THING_ID_DESC)]) -> Any:
    """Get a thing's definition (WoT model reference). Wraps GET /things/{thingId}/definition."""
    return _get_or_empty(client, f"/api/2/things/{thing_id}/definition", {}, f"Failed to fetch definition for '{thing_id}'")


@mcp.tool()
def set_thing_definition(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    definition: Annotated[str, Field(description="Definition identifier, e.g. 'com.acme:coffeebrewer:0.1.0'.")],
) -> dict[str, Any]:
    """Set a thing's definition. Wraps PUT /things/{thingId}/definition."""
    try:
        resp = client.put(f"/api/2/things/{thing_id}/definition", json=definition)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to set definition for '{thing_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request to set definition of '{thing_id}' failed: {e}") from e
    return {"thingId": thing_id, "definition": definition}


@mcp.tool()
def delete_thing_definition(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Remove a thing's definition. Wraps DELETE /things/{thingId}/definition."""
    _require_confirm(confirm, f"delete definition of thing '{thing_id}'")
    return _delete(client, f"/api/2/things/{thing_id}/definition", f"Failed to delete definition of '{thing_id}'")


@mcp.tool()
def whoami() -> dict[str, Any]:
    """Return the identity Ditto has authenticated this connector as. Wraps GET /api/2/whoami.

    Useful to sanity-check DITTO_USERNAME/DITTO_PASSWORD/DITTO_BEARER_TOKEN configuration.
    """
    try:
        resp = client.get("/api/2/whoami")
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"whoami failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"whoami request failed: {e}") from e
    return dict(resp.json())


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------


@mcp.tool()
def get_thing_attributes(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    path: Annotated[str | None, Field(description=_JSON_POINTER_DESC)] = None,
) -> Any:
    """Get a thing's attributes, or one attribute by JSON pointer path.

    Wraps GET /things/{thingId}/attributes[/{path}].
    """
    return _get_or_empty(
        client,
        _sub_path(f"/api/2/things/{thing_id}/attributes", path),
        {},
        f"Failed to fetch attributes for '{thing_id}'",
    )


@mcp.tool()
def set_thing_attributes(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    value: Annotated[Any, Field(description="Value to set. A JSON object if path is omitted, any JSON value otherwise.")],
    path: Annotated[str | None, Field(description=_JSON_POINTER_DESC)] = None,
    overwrite: Annotated[bool, Field(description=_OVERWRITE_DESC)] = False,
) -> dict[str, Any]:
    """Set a thing's whole attributes object, or one attribute by path.

    Wraps PUT /things/{thingId}/attributes[/{path}].
    """
    _create_or_replace(
        client,
        _sub_path(f"/api/2/things/{thing_id}/attributes", path),
        value,
        overwrite,
        f"Attributes of '{thing_id}'" + (f" at '{path}'" if path else ""),
    )
    return {"thingId": thing_id, "path": path, "value": value, "updated": True}


@mcp.tool()
def delete_thing_attributes(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    path: Annotated[str | None, Field(description=_JSON_POINTER_DESC)] = None,
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Delete a thing's whole attributes object, or one attribute by path.

    Wraps DELETE /things/{thingId}/attributes[/{path}].
    """
    _require_confirm(confirm, f"delete attributes of thing '{thing_id}'")
    return _delete(
        client,
        _sub_path(f"/api/2/things/{thing_id}/attributes", path),
        f"Failed to delete attributes of '{thing_id}'",
    )


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------


@mcp.tool()
def get_thing_features(thing_id: Annotated[str, Field(description=_THING_ID_DESC)]) -> dict[str, Any]:
    """Fetch only the feature state (sensor/actuator data) for a thing.

    Wraps GET /api/2/things/{thingId}/features. Ditto returns 404 both when the
    thing doesn't exist and when it exists but has no features defined; both
    cases are normalized here to an empty dict.
    """
    result = _get_or_empty(
        client, f"/api/2/things/{thing_id}/features", {}, f"Failed to fetch features for '{thing_id}'"
    )
    return dict(result) if result else {}


@mcp.tool()
def get_feature(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
) -> dict[str, Any]:
    """Fetch a single feature (definition + properties + desiredProperties).

    Wraps GET /things/{thingId}/features/{featureId}.
    """
    result = _get_or_empty(
        client,
        f"/api/2/things/{thing_id}/features/{feature_id}",
        {},
        f"Failed to fetch feature '{feature_id}' of '{thing_id}'",
    )
    return dict(result) if result else {}


@mcp.tool()
def put_feature(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
    feature: Annotated[dict[str, Any], Field(description="Full feature JSON (definition, properties).")],
    overwrite: Annotated[bool, Field(description=_OVERWRITE_DESC)] = False,
) -> dict[str, Any]:
    """Create or replace a whole feature. Wraps PUT /things/{thingId}/features/{featureId}."""
    resp = _create_or_replace(
        client,
        f"/api/2/things/{thing_id}/features/{feature_id}",
        feature,
        overwrite,
        f"Feature '{feature_id}' of '{thing_id}'",
    )
    return dict(resp.json()) if resp.content else {"thingId": thing_id, "featureId": feature_id, "updated": True}


@mcp.tool()
def delete_feature(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Delete a whole feature. Wraps DELETE /things/{thingId}/features/{featureId}."""
    _require_confirm(confirm, f"delete feature '{feature_id}' of thing '{thing_id}'")
    return _delete(
        client,
        f"/api/2/things/{thing_id}/features/{feature_id}",
        f"Failed to delete feature '{feature_id}' of '{thing_id}'",
    )


@mcp.tool()
def get_feature_properties(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
    path: Annotated[str | None, Field(description=_JSON_POINTER_DESC)] = None,
    desired: Annotated[bool, Field(description="Read desiredProperties instead of properties.")] = False,
) -> Any:
    """Get a feature's properties (or desiredProperties), or one property by path.

    Wraps GET /things/{thingId}/features/{featureId}/(desired)properties[/{path}].
    """
    resource = "desiredProperties" if desired else "properties"
    return _get_or_empty(
        client,
        _sub_path(f"/api/2/things/{thing_id}/features/{feature_id}/{resource}", path),
        {},
        f"Failed to fetch {resource} for feature '{feature_id}' of '{thing_id}'",
    )


@mcp.tool()
def set_feature_properties(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
    value: Annotated[Any, Field(description="Value to set. A JSON object if path is omitted, any JSON value otherwise.")],
    path: Annotated[str | None, Field(description=_JSON_POINTER_DESC)] = None,
    desired: Annotated[bool, Field(description="Write desiredProperties instead of properties.")] = False,
    overwrite: Annotated[bool, Field(description=_OVERWRITE_DESC)] = False,
) -> dict[str, Any]:
    """Set a feature's whole properties (or desiredProperties) object, or one property by path.

    Wraps PUT /things/{thingId}/features/{featureId}/(desired)properties[/{path}].
    """
    resource = "desiredProperties" if desired else "properties"
    _create_or_replace(
        client,
        _sub_path(f"/api/2/things/{thing_id}/features/{feature_id}/{resource}", path),
        value,
        overwrite,
        f"{resource} of feature '{feature_id}' of '{thing_id}'" + (f" at '{path}'" if path else ""),
    )
    return {"thingId": thing_id, "featureId": feature_id, "path": path, "value": value, "updated": True}


@mcp.tool()
def delete_feature_properties(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
    path: Annotated[str | None, Field(description=_JSON_POINTER_DESC)] = None,
    desired: Annotated[bool, Field(description="Delete from desiredProperties instead of properties.")] = False,
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Delete a feature's whole properties (or desiredProperties) object, or one property by path.

    Wraps DELETE /things/{thingId}/features/{featureId}/(desired)properties[/{path}].
    """
    _require_confirm(confirm, f"delete properties of feature '{feature_id}' of thing '{thing_id}'")
    resource = "desiredProperties" if desired else "properties"
    return _delete(
        client,
        _sub_path(f"/api/2/things/{thing_id}/features/{feature_id}/{resource}", path),
        f"Failed to delete {resource} of feature '{feature_id}' of '{thing_id}'",
    )


@mcp.tool()
def get_feature_definition(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
) -> Any:
    """Get a feature's definition. Wraps GET .../features/{featureId}/definition."""
    return _get_or_empty(
        client,
        f"/api/2/things/{thing_id}/features/{feature_id}/definition",
        {},
        f"Failed to fetch definition of feature '{feature_id}' of '{thing_id}'",
    )


@mcp.tool()
def set_feature_definition(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
    definition: Annotated[list[str], Field(description="List of definition identifiers, e.g. ['com.acme:coffeebrewer:0.1.0'].")],
) -> dict[str, Any]:
    """Set a feature's definition. Wraps PUT .../features/{featureId}/definition."""
    try:
        resp = client.put(f"/api/2/things/{thing_id}/features/{feature_id}/definition", json=definition)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(
            f"Failed to set definition of feature '{feature_id}' of '{thing_id}' ({e.response.status_code}): {e.response.text}"
        ) from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request to set feature definition failed: {e}") from e
    return {"thingId": thing_id, "featureId": feature_id, "definition": definition}


@mcp.tool()
def delete_feature_definition(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    feature_id: Annotated[str, Field(description=_FEATURE_ID_DESC)],
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Remove a feature's definition. Wraps DELETE .../features/{featureId}/definition."""
    _require_confirm(confirm, f"delete definition of feature '{feature_id}' of thing '{thing_id}'")
    return _delete(
        client,
        f"/api/2/things/{thing_id}/features/{feature_id}/definition",
        f"Failed to delete definition of feature '{feature_id}' of '{thing_id}'",
    )


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


@mcp.tool()
def send_message(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    subject: Annotated[str, Field(description="Message subject, e.g. 'makeCoffee'.")],
    payload: Annotated[Any, Field(description="Message payload. Sent as JSON.")],
    feature_id: Annotated[
        str | None, Field(description="Scope the message to this feature instead of the whole thing.")
    ] = None,
    direction: Annotated[
        Literal["inbox", "outbox"], Field(description="'inbox' sends TO the thing/feature, 'outbox' FROM it.")
    ] = "inbox",
    timeout: Annotated[
        int, Field(description="Seconds to wait for a response. 0 sends fire-and-forget.", ge=0, le=60)
    ] = 10,
) -> Any:
    """Send a live message to (or from) a thing or one of its features.

    Wraps POST /things/{thingId}/[features/{featureId}/]{direction}/messages/{subject}.
    """
    base = f"/api/2/things/{thing_id}"
    if feature_id:
        base += f"/features/{feature_id}"
    path = f"{base}/{direction}/messages/{subject}"
    try:
        resp = client.post(path, json=payload, params={"timeout": timeout})
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Message '{subject}' to '{thing_id}' failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Message request to '{thing_id}' failed: {e}") from e
    if not resp.content:
        return {"thingId": thing_id, "subject": subject, "status": resp.status_code}
    try:
        return resp.json()
    except ValueError:
        return resp.text


@mcp.tool()
def claim_thing(
    thing_id: Annotated[str, Field(description=_THING_ID_DESC)],
    payload: Annotated[Any, Field(description="Optional claim payload sent to the thing's registered handler.")] = None,
    timeout: Annotated[int, Field(description="Seconds to wait for a response.", ge=0, le=60)] = 10,
) -> Any:
    """Send a claim message to gain access to a thing. Wraps POST /things/{thingId}/inbox/claim."""
    try:
        resp = client.post(f"/api/2/things/{thing_id}/inbox/claim", json=payload, params={"timeout": timeout})
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Claim of '{thing_id}' failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Claim request for '{thing_id}' failed: {e}") from e
    if not resp.content:
        return {"thingId": thing_id, "status": resp.status_code}
    try:
        return resp.json()
    except ValueError:
        return resp.text


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@mcp.tool()
def get_policy(policy_id: Annotated[str, Field(description=_POLICY_ID_DESC)]) -> dict[str, Any]:
    """Fetch a policy. Wraps GET /api/2/policies/{policyId}."""
    try:
        resp = client.get(f"/api/2/policies/{policy_id}")
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch policy '{policy_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for policy '{policy_id}' failed: {e}") from e
    return dict(resp.json())


@mcp.tool()
def put_policy(
    policy_id: Annotated[str, Field(description=_POLICY_ID_DESC)],
    policy: Annotated[dict[str, Any], Field(description="Full policy JSON (entries with subjects/resources).")],
    overwrite: Annotated[bool, Field(description=_OVERWRITE_DESC)] = False,
) -> dict[str, Any]:
    """Create a new policy, or replace an existing one (with overwrite=True).

    Wraps PUT /api/2/policies/{policyId}.
    """
    resp = _create_or_replace(client, f"/api/2/policies/{policy_id}", policy, overwrite, f"Policy '{policy_id}'")
    return dict(resp.json()) if resp.content else {"policyId": policy_id, "updated": True}


@mcp.tool()
def delete_policy(
    policy_id: Annotated[str, Field(description=_POLICY_ID_DESC)],
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Delete a policy. Wraps DELETE /api/2/policies/{policyId}. Irreversible.

    Note: things still referencing this policy will become inaccessible.
    """
    _require_confirm(confirm, f"delete policy '{policy_id}'")
    return _delete(client, f"/api/2/policies/{policy_id}", f"Failed to delete policy '{policy_id}'")


@mcp.tool()
def get_policy_entries(
    policy_id: Annotated[str, Field(description=_POLICY_ID_DESC)],
    label: Annotated[str | None, Field(description="Specific entry label to fetch. Omit to fetch all entries.")] = None,
) -> Any:
    """Get all policy entries, or one entry by label. Wraps GET /policies/{policyId}/entries[/{label}]."""
    return _get_or_empty(
        client,
        _sub_path(f"/api/2/policies/{policy_id}/entries", label),
        {},
        f"Failed to fetch entries of policy '{policy_id}'",
    )


@mcp.tool()
def set_policy_entry(
    policy_id: Annotated[str, Field(description=_POLICY_ID_DESC)],
    label: Annotated[str, Field(description="Entry label, e.g. 'DEFAULT' or 'DEVICES'.")],
    entry: Annotated[dict[str, Any], Field(description="Policy entry JSON: {'subjects': {...}, 'resources': {...}}.")],
    overwrite: Annotated[bool, Field(description=_OVERWRITE_DESC)] = False,
) -> dict[str, Any]:
    """Create or replace one policy entry. Wraps PUT /policies/{policyId}/entries/{label}."""
    resp = _create_or_replace(
        client,
        f"/api/2/policies/{policy_id}/entries/{label}",
        entry,
        overwrite,
        f"Policy entry '{label}' of '{policy_id}'",
    )
    return dict(resp.json()) if resp.content else {"policyId": policy_id, "label": label, "updated": True}


@mcp.tool()
def delete_policy_entry(
    policy_id: Annotated[str, Field(description=_POLICY_ID_DESC)],
    label: Annotated[str, Field(description="Entry label to delete.")],
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Delete one policy entry. Wraps DELETE /policies/{policyId}/entries/{label}."""
    _require_confirm(confirm, f"delete policy entry '{label}' of policy '{policy_id}'")
    return _delete(
        client,
        f"/api/2/policies/{policy_id}/entries/{label}",
        f"Failed to delete entry '{label}' of policy '{policy_id}'",
    )


# ---------------------------------------------------------------------------
# Connectivity (requires DITTO_DEVOPS_USERNAME/PASSWORD)
# ---------------------------------------------------------------------------

_CONNECTION_COMMANDS = {
    "connectivity.commands:openConnection",
    "connectivity.commands:closeConnection",
    "connectivity.commands:resetConnectionMetrics",
    "connectivity.commands:enableConnectionLogs",
    "connectivity.commands:resetConnectionLogs",
}


@mcp.tool()
def list_connections(ids_only: Annotated[bool, Field(description="Return only connection IDs, not full configs.")] = False) -> Any:
    """List all configured connections. Wraps GET /api/2/connections. Requires devops credentials."""
    try:
        resp = devops_client.get("/api/2/connections", params={"ids-only": str(ids_only).lower()} if ids_only else {})
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to list connections ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request to list connections failed: {e}") from e
    return resp.json()


@mcp.tool()
def get_connection(connection_id: Annotated[str, Field(description=_CONNECTION_ID_DESC)]) -> dict[str, Any]:
    """Fetch a connection's config. Wraps GET /api/2/connections/{connectionId}. Requires devops credentials."""
    try:
        resp = devops_client.get(f"/api/2/connections/{connection_id}")
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch connection '{connection_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for connection '{connection_id}' failed: {e}") from e
    return dict(resp.json())


@mcp.tool()
def create_connection(
    connection: Annotated[
        dict[str, Any], Field(description="New connection JSON (connectionType, connectionStatus, sources, targets, ...).")
    ],
    dry_run: Annotated[bool, Field(description="If True, only test connectivity without persisting the connection.")] = False,
) -> dict[str, Any]:
    """Create a new connection; its ID is generated by Ditto. Wraps POST /api/2/connections.

    Requires devops credentials.
    """
    try:
        resp = devops_client.post("/api/2/connections", json=connection, params={"dry-run": str(dry_run).lower()})
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to create connection ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request to create connection failed: {e}") from e
    return dict(resp.json()) if resp.content else {"dry_run": dry_run, "created": True}


@mcp.tool()
def update_connection(
    connection_id: Annotated[str, Field(description=_CONNECTION_ID_DESC)],
    connection: Annotated[dict[str, Any], Field(description="Full replacement connection JSON.")],
) -> dict[str, Any]:
    """Update an existing connection's config. Wraps PUT /api/2/connections/{connectionId}.

    Unlike thing/policy PUT, this only updates — Ditto returns 404 if the
    connection doesn't already exist. Requires devops credentials.
    """
    try:
        resp = devops_client.put(f"/api/2/connections/{connection_id}", json=connection)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to update connection '{connection_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request to update connection '{connection_id}' failed: {e}") from e
    return {"connectionId": connection_id, "updated": True}


@mcp.tool()
def delete_connection(
    connection_id: Annotated[str, Field(description=_CONNECTION_ID_DESC)],
    confirm: Annotated[bool, Field(description=_CONFIRM_DESC)] = False,
) -> dict[str, Any]:
    """Delete a connection. Wraps DELETE /api/2/connections/{connectionId}. Irreversible.

    Requires devops credentials.
    """
    _require_confirm(confirm, f"delete connection '{connection_id}'")
    return _delete(devops_client, f"/api/2/connections/{connection_id}", f"Failed to delete connection '{connection_id}'")


@mcp.tool()
def get_connection_status(connection_id: Annotated[str, Field(description=_CONNECTION_ID_DESC)]) -> dict[str, Any]:
    """Get a connection's live status. Wraps GET /connections/{connectionId}/status. Requires devops credentials."""
    try:
        resp = devops_client.get(f"/api/2/connections/{connection_id}/status")
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch status of '{connection_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for status of '{connection_id}' failed: {e}") from e
    return dict(resp.json())


@mcp.tool()
def get_connection_metrics(connection_id: Annotated[str, Field(description=_CONNECTION_ID_DESC)]) -> dict[str, Any]:
    """Get a connection's metrics. Wraps GET /connections/{connectionId}/metrics. Requires devops credentials."""
    try:
        resp = devops_client.get(f"/api/2/connections/{connection_id}/metrics")
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch metrics of '{connection_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for metrics of '{connection_id}' failed: {e}") from e
    return dict(resp.json())


@mcp.tool()
def get_connection_logs(connection_id: Annotated[str, Field(description=_CONNECTION_ID_DESC)]) -> dict[str, Any]:
    """Get a connection's logs. Wraps GET /connections/{connectionId}/logs.

    Logging must first be enabled via send_connection_command(connection_id,
    "connectivity.commands:enableConnectionLogs") — it's on by default when a
    connection is created or opened. Requires devops credentials.
    """
    try:
        resp = devops_client.get(f"/api/2/connections/{connection_id}/logs")
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch logs of '{connection_id}' ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for logs of '{connection_id}' failed: {e}") from e
    return dict(resp.json())


@mcp.tool()
def send_connection_command(
    connection_id: Annotated[str, Field(description=_CONNECTION_ID_DESC)],
    command: Annotated[
        str,
        Field(
            description=(
                "One of: connectivity.commands:openConnection, connectivity.commands:closeConnection, "
                "connectivity.commands:resetConnectionMetrics, connectivity.commands:enableConnectionLogs, "
                "connectivity.commands:resetConnectionLogs."
            )
        ),
    ],
) -> str:
    """Send a lifecycle/diagnostic command to a connection. Wraps POST /connections/{connectionId}/command.

    Requires devops credentials.
    """
    if command not in _CONNECTION_COMMANDS:
        raise ValueError(f"Unsupported command '{command}'. Must be one of: {sorted(_CONNECTION_COMMANDS)}")
    try:
        resp = devops_client.post(
            f"/api/2/connections/{connection_id}/command",
            content=command,
            headers={"Content-Type": "text/plain"},
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Command '{command}' on '{connection_id}' failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Command request to '{connection_id}' failed: {e}") from e
    return resp.text


# ---------------------------------------------------------------------------
# DevOps (requires DITTO_DEVOPS_USERNAME/PASSWORD)
# ---------------------------------------------------------------------------


@mcp.tool()
def get_logging_config(
    module_name: Annotated[str | None, Field(description="Specific service module (e.g. 'gateway'). Omit for all.")] = None,
) -> Any:
    """Get currently configured log levels. Wraps GET /devops/logging[/{moduleName}]. Requires devops credentials."""
    path = _sub_path("/devops/logging", module_name)
    try:
        resp = devops_client.get(path)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch logging config ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for logging config failed: {e}") from e
    return resp.json()


@mcp.tool()
def set_logging_config(
    level: Annotated[str, Field(description="Log level, e.g. 'INFO', 'DEBUG', 'WARN', 'ERROR'.")],
    logger: Annotated[str, Field(description="Logger/package name, e.g. 'org.eclipse.ditto'.")],
    module_name: Annotated[str | None, Field(description="Restrict the change to this service module. Omit for all.")] = None,
) -> Any:
    """Set a log level for a logger. Wraps PUT /devops/logging[/{moduleName}]. Requires devops credentials."""
    path = _sub_path("/devops/logging", module_name)
    try:
        resp = devops_client.put(path, json={"level": level, "logger": logger})
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to set logging config ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request to set logging config failed: {e}") from e
    return resp.json()


@mcp.tool()
def get_devops_config(
    path: Annotated[
        str | None,
        Field(description="Dotted config path to retrieve, e.g. 'ditto.gateway.authentication'. Strongly recommended to avoid a huge response."),
    ] = None,
) -> Any:
    """Get cluster-wide runtime configuration. Wraps GET /devops/config?path=... Requires devops credentials."""
    try:
        resp = devops_client.get("/devops/config", params={"path": path} if path else {})
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Failed to fetch devops config ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Request for devops config failed: {e}") from e
    return resp.json()


@mcp.tool()
def send_devops_piggyback(
    command: Annotated[dict[str, Any], Field(description="Piggyback command body, see Ditto DevOps API docs for shapes.")],
    service_name: Annotated[str | None, Field(description="Restrict to this service (e.g. 'things'). Omit to broadcast.")] = None,
    instance_index: Annotated[str | None, Field(description="Restrict to this service instance. Requires service_name.")] = None,
    timeout: Annotated[int | None, Field(description="Seconds to wait for a response.", ge=0, le=60)] = None,
) -> Any:
    """Send a low-level admin (piggyback) command to the Ditto cluster.

    Wraps POST /devops/piggyback[/{serviceName}[/{instanceIndex}]]. Requires devops credentials.
    This is Ditto's most powerful/least guarded admin API — use with care.
    """
    if instance_index and not service_name:
        raise ValueError("instance_index requires service_name to also be set.")
    path = "/devops/piggyback"
    if service_name:
        path += f"/{service_name}"
        if instance_index:
            path += f"/{instance_index}"
    try:
        resp = devops_client.post(path, json=command, params={"timeout": timeout} if timeout is not None else {})
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Piggyback command failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Piggyback command request failed: {e}") from e
    return resp.json() if resp.content else {"sent": True}


# ---------------------------------------------------------------------------
# Live change events (poll-style approximation of Ditto's SSE API)
# ---------------------------------------------------------------------------


@mcp.tool()
def poll_thing_changes(
    thing_ids: Annotated[list[str] | None, Field(description="Restrict to these thing IDs. Omit to watch all visible things.")] = None,
    namespaces: Annotated[list[str] | None, Field(description="Restrict to these namespaces.")] = None,
    filter: Annotated[str | None, Field(description="Ditto RQL filter expression.")] = None,
    fields: Annotated[list[str] | None, Field(description=_FIELDS_DESC)] = None,
    duration_seconds: Annotated[
        float, Field(description="Wall-clock cutoff: stop listening after this many seconds.", ge=1, le=60)
    ] = 10.0,
    max_events: Annotated[int, Field(description="Stop early once this many events are collected.", ge=1, le=500)] = 50,
) -> dict[str, Any]:
    """Open a short-lived SSE connection and collect live thing-change events.

    Approximates Ditto's persistent-connection change feed (GET /api/2/things
    with Accept: text/event-stream) within a single request/response tool call.
    Each event is a partial update (only the changed portion of the thing).

    Ditto's SSE stream sends periodic empty `data:` keepalive lines even when
    nothing has changed; the deadline is checked on every line received
    (including keepalives), not just on real events, so this always returns
    within duration_seconds regardless of how quiet or chatty the stream is.
    """
    params: dict[str, Any] = {}
    if thing_ids:
        params["ids"] = ",".join(thing_ids)
    if namespaces:
        params["namespaces"] = ",".join(namespaces)
    if filter:
        params["filter"] = filter
    if fields:
        params["fields"] = ",".join(fields)

    events: list[Any] = []
    stopped_reason = "timeout"
    deadline = time.monotonic() + duration_seconds

    try:
        with client.stream(
            "GET",
            "/api/2/things",
            params=params,
            headers={"Accept": "text/event-stream"},
            timeout=httpx.Timeout(connect=10.0, read=duration_seconds + 15.0, write=10.0, pool=10.0),
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if time.monotonic() >= deadline:
                    break
                if not line or not line.startswith("data:"):
                    continue
                payload = line[len("data:") :].strip()
                if not payload:
                    continue
                try:
                    events.append(json.loads(payload))
                except json.JSONDecodeError:
                    events.append(payload)
                if len(events) >= max_events:
                    stopped_reason = "max_events"
                    break
    except httpx.ReadTimeout:
        stopped_reason = "timeout"
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Event stream failed ({e.response.status_code}): {e.response.text}") from e
    except httpx.HTTPError as e:
        raise RuntimeError(f"Event stream request failed: {e}") from e

    return {"events": events, "count": len(events), "stopped_reason": stopped_reason}


def main() -> None:
    transport, host, port = _get_mcp_init_vars()
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=transport, transport_options={"host": host, "port": port})


if __name__ == "__main__":
    main()
