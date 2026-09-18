"""CIDR parsing and address-space arithmetic (stdlib ``ipaddress`` only).

All address ranges are represented as half-open integer intervals
``[start, end)``; this works uniformly for IPv4 and IPv6.
"""

import ipaddress
from collections.abc import Iterable

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_cidr(value: str) -> Network:
    """Strictly parse ``address/prefix``.

    Non-canonical hosts (e.g. ``192.168.1.5/24``) are rejected with
    ValueError, as are malformed prefixes.
    """
    if not isinstance(value, str):
        raise ValueError("CIDR must be a string")
    try:
        return ipaddress.ip_network(value.strip(), strict=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid or non-canonical CIDR '{value}': {exc}")


def bounds(net: Network) -> tuple[int, int]:
    return int(net.network_address), int(net.broadcast_address) + 1


def overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _merge_intervals(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def free_intervals(
    pool_start: int,
    pool_end: int,
    occupied: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Subtract merged occupied intervals from the pool."""
    free: list[tuple[int, int]] = []
    cursor = pool_start
    for start, end in _merge_intervals(occupied):
        if end <= cursor:
            continue
        if start >= pool_end:
            break
        if start > cursor:
            free.append((cursor, min(start, pool_end)))
        cursor = max(cursor, end)
        if cursor >= pool_end:
            break
    if cursor < pool_end:
        free.append((cursor, pool_end))
    return free


def smallest_subnet(
    free: list[tuple[int, int]], prefix_len: int, max_prefix: int
) -> tuple[int, int] | None:
    """Find the legal ``prefix_len`` subnet with the smallest start address.

    The first free interval (ordered by start) that is wide enough yields
    the globally smallest aligned subnet start.
    """
    if prefix_len > max_prefix:
        return None
    size = 1 << (max_prefix - prefix_len)
    mask = size - 1
    for start, end in free:
        aligned = (start + mask) & ~mask
        if aligned + size <= end:
            return aligned, aligned + size
    return None


def collapse(
    intervals: Iterable[tuple[int, int]], version: int
) -> list[str]:
    """Merge free space into the minimal set of CIDR strings.

    Adjacent/overlapping intervals are joined, then each interval is
    greedily cut into aligned power-of-two blocks, largest first — the
    standard minimal representation of an address range.
    """
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    max_prefix = 32 if version == 4 else 128
    result: list[str] = []
    for start, end in _merge_intervals(intervals):
        while start < end:
            # Largest alignment offered by the start address itself.
            limit_align = (start & -start).bit_length() - 1 if start else max_prefix
            # Largest block that still fits the remaining space.
            limit_fit = (end - start).bit_length() - 1
            block_bits = min(limit_align, limit_fit, max_prefix)
            size = 1 << block_bits
            net = ipaddress.ip_network(
                (cls(start), max_prefix - block_bits), strict=False
            )
            result.append(str(net))
            start += size
    return result
