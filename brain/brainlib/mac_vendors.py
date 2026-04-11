from __future__ import annotations

from functools import lru_cache


def normalize_mac_vendor(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


@lru_cache(maxsize=1)
def _lookup_fn():
    try:
        from pymanuf import lookup  # type: ignore
    except Exception:
        return None
    return lookup


def lookup_mac_vendor(mac_address: str | None) -> str | None:
    if not mac_address:
        return None

    lookup = _lookup_fn()
    if lookup is None:
        return None

    try:
        result = lookup(mac_address)
    except Exception:
        return None

    return normalize_mac_vendor(str(result)) if result else None


def resolved_mac_vendor(mac_address: str | None, observed_vendor: str | None) -> str | None:
    return normalize_mac_vendor(observed_vendor) or lookup_mac_vendor(mac_address)
