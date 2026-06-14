from __future__ import annotations

from typing import Any, cast
from urllib.parse import urlparse


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_domain(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def normalize_npm_proxy_host(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize an NPM proxy host using a strict non-secret allowlist.

    Do not copy NPM meta, advanced_config, certificate objects, access lists,
    owners, tokens, or other non-allowlisted fields into raw_json.
    """

    routes: list[dict[str, Any]] = []
    proxy_host_id = record.get("id")
    certificate_id = record.get("certificate_id")
    upstream_port = _as_int(record.get("forward_port"))
    for domain in _first_domain(record.get("domain_names")):
        routes.append(
            {
                "source": "npm",
                "domain": domain,
                "scheme": record.get("forward_scheme"),
                "upstream_host": record.get("forward_host"),
                "upstream_port": upstream_port,
                "tls_status": "configured" if certificate_id else "missing",
                "certificate_status": f"certificate_id:{certificate_id}" if certificate_id else "missing",
                "force_ssl": _as_bool(record.get("ssl_forced")),
                "http2_support": _as_bool(record.get("http2_support")),
                "block_exploits": _as_bool(record.get("block_exploits")),
                "websocket_support": _as_bool(record.get("allow_websocket_upgrade")),
                "raw_json": {
                    "proxy_host_id": proxy_host_id,
                    "certificate_id": certificate_id,
                    "caching_enabled": _as_bool(record.get("caching_enabled")),
                },
            }
        )
    return routes


def normalize_hcm_target(target: dict[str, Any]) -> dict[str, Any]:
    route_url = str(target.get("route_url") or target.get("url") or "")
    backend_url = str(target.get("backend_url") or target.get("target_url") or "")
    route = urlparse(route_url)
    backend = urlparse(backend_url)
    tls_raw = target.get("tls")
    health_raw = target.get("health")
    tls = cast(dict[str, Any], tls_raw) if isinstance(tls_raw, dict) else {}
    health = cast(dict[str, Any], health_raw) if isinstance(health_raw, dict) else {}
    tls_status = tls.get("status") or target.get("tls_status")

    return {
        "source": "hcm",
        "domain": route.hostname or route.netloc or route_url,
        "scheme": backend.scheme or None,
        "upstream_host": backend.hostname,
        "upstream_port": backend.port,
        "tls_status": tls_status,
        "certificate_status": tls_status,
        "force_ssl": None,
        "http2_support": None,
        "block_exploits": None,
        "websocket_support": None,
        "raw_json": {
            "name": target.get("name"),
            "route_url": route_url,
            "backend_url": backend_url,
            "health_status": health.get("status") or target.get("health_status"),
            "tls_issuer": tls.get("issuer") or target.get("tls_issuer"),
            "tls_not_after": tls.get("not_after") or target.get("tls_not_after"),
        },
    }


def normalize_heimdall_link(record: dict[str, Any]) -> dict[str, Any]:
    title = str(record.get("title") or record.get("name") or "Untitled")
    url = str(record.get("url") or record.get("link") or "")
    parsed = urlparse(url)
    host = parsed.hostname
    scheme = parsed.scheme.lower()
    is_ip = bool(host and all(part.isdigit() for part in host.split(".") if part) and host.count(".") == 3)

    if scheme == "https" and host and not is_ip:
        link_kind = "named_https"
        hygiene_status = "preferred"
        preferred_route_domain = host
    elif scheme == "http" and is_ip:
        link_kind = "raw_ip"
        hygiene_status = "weak_raw_http_ip"
        preferred_route_domain = None
    elif scheme == "http":
        link_kind = "named_http"
        hygiene_status = "weak_plain_http"
        preferred_route_domain = None
    elif is_ip:
        link_kind = "raw_ip"
        hygiene_status = "weak_raw_ip"
        preferred_route_domain = None
    else:
        link_kind = "unknown"
        hygiene_status = "observed"
        preferred_route_domain = None

    return {
        "source": "heimdall",
        "title": title,
        "url": url,
        "normalized_host": host,
        "link_kind": link_kind,
        "preferred_route_domain": preferred_route_domain,
        "hygiene_status": hygiene_status,
        "raw_json": {},
    }


def normalize_dns_answer(
    *,
    hostname: str,
    resolver: str,
    record_type: str = "A",
    values: list[str] | tuple[str, ...] | None = None,
    planned: bool = False,
) -> list[dict[str, Any]]:
    cleaned = [str(value).strip() for value in (values or []) if str(value).strip()]
    if not cleaned:
        return [
            {
                "hostname": hostname,
                "resolver": resolver,
                "record_type": record_type,
                "record_value": "<unresolved>",
                "status": "planned_unresolved" if planned else "unresolved",
                "raw_json": {"planned": planned},
            }
        ]

    return [
        {
            "hostname": hostname,
            "resolver": resolver,
            "record_type": record_type,
            "record_value": value,
            "status": "observed",
            "raw_json": {"planned": planned},
        }
        for value in cleaned
    ]
