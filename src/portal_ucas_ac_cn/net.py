"""Local network helpers."""

from __future__ import annotations

import socket
import struct

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix
    fcntl = None  # type: ignore[assignment]

from .api import info

# ioctl request codes for SIOCGIFADDR (Linux, macOS/BSD).
_SIOCGIFADDR = (0x8915, 0xC0206921)

# Interfaces that are unlikely to carry the campus uplink.
_VIRTUAL_PREFIXES = (
    "lo",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "utun",
    "tun",
    "tap",
    "wg",
    "zt",
    "tailscale",
    "gif",
    "stf",
    "awdl",
    "llw",
    "anpi",
    "nan",
    "ap",
)


def _interface_addresses() -> list[tuple[str, str]]:
    """Return ``(interface, IPv4)`` pairs for every configured interface."""
    found: list[tuple[str, str]] = []
    if fcntl is not None:
        try:
            names = socket.if_nameindex()
        except OSError:
            names = []
        for _, name in names:
            for request in _SIOCGIFADDR:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        data = fcntl.ioctl(
                            sock.fileno(),
                            request,
                            struct.pack("256s", name[:15].encode()),
                        )
                    address = socket.inet_ntoa(data[20:24])
                except OSError:
                    continue
                found.append((name, address))
                break
    if not found:
        try:
            for entry in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                found.append(("", entry[4][0]))
        except OSError:
            pass
    return found


def _routed_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("223.5.5.5", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def _portal_ip() -> str | None:
    try:
        data = info()
    except Exception:
        return None
    for key in ("online_ip", "client_ip", "ip"):
        address = (data.get(key) or "").strip()
        if address and address != "0.0.0.0":
            return address
    return None


def detect_ip() -> str | None:
    """Best guess for this host's campus-network address.

    The campus network hands out addresses in ``10.0.0.0/8``, while a host may
    also have VPN or virtual-switch addresses, so prefer a ``10.`` address on a
    physical interface. Only if there is none do we fall back to the route used
    to reach the internet and then to the portal's own view.
    """
    addresses = _interface_addresses()
    campus = [(name, address) for name, address in addresses if address.startswith("10.")]
    for name, address in campus:
        if not name.startswith(_VIRTUAL_PREFIXES):
            return address
    if campus:
        return campus[0][1]
    return _routed_ip() or _portal_ip()
