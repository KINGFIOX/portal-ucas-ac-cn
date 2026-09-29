"""Command-line entry point.

Default mode signs a device in. ``--status`` inspects a session without
credentials, which is also the quickest way to spot a session that landed on
the wrong NAS (online but zero traffic counters).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .api import info, login, logout
from .net import detect_ip
from .prompt import ask, validate_ac_id, validate_email, validate_ip


def _fmt_bytes(count: int) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{count} B"


def _fmt_seconds(seconds: int) -> str:
    hours, rest = divmod(int(seconds), 3600)
    return f"{hours}h{rest // 60:02d}m"


def show_status(data: dict, ip: str) -> bool:
    """Print a session summary; return True when the address is online."""
    if data.get("error") != "ok":
        print(f"{ip}: not online ({data.get('error', 'unknown')})")
        return False
    traffic = int(data.get("bytes_in", 0)) + int(data.get("bytes_out", 0))
    print(
        f"{ip}: online as {data.get('user_name') or '?'}"
        f"  in {_fmt_bytes(int(data.get('bytes_in', 0)))}"
        f" / out {_fmt_bytes(int(data.get('bytes_out', 0)))}"
        f"  usage {_fmt_seconds(data.get('sum_seconds', 0))} (account total)"
        f"  domain {data.get('domain') or '?'}"
    )
    if traffic == 0:
        print(
            "  warning: this session has carried no traffic. It was most likely\n"
            "  created with an ac_id that does not match the device's NAS — the\n"
            "  portal lists it as online but the gateway never opens. Re-login\n"
            "  with the device's own ac_id (see --ac-id in --help)."
        )
    return True


def _device_hints(ip: str, local_ip: str) -> None:
    if ip == local_ip:
        return
    print(
        f"""
On the device ({ip}), verify and find its own ac_id with BusyBox wget:

  wget -T 8 -O /dev/null http://www.baidu.com && echo IPv4 OK
  wget -S -O /dev/null --no-check-certificate \\
    https://portal.ucas.ac.cn/index_1.html 2>&1 | grep -i location

The second command must be a real GET (the portal 404s HEAD requests, so
--spider and curl -I do not work). It prints 'Location: ...ac_id=<N>...' —
<N> is the NAS id of the device's subnet; pass it here as --ac-id if the
login above did not open IPv4."""
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ucas-portal",
        description="Sign a device into the UCAS (Srun) campus network.",
    )
    parser.add_argument("--email", help="account (default: $UCAS_PORTAL_EMAIL, then prompt)")
    parser.add_argument("--ip", help="device IPv4 to sign in (default: prompt)")
    parser.add_argument(
        "--ac-id",
        help="NAS id of the device's subnet (default: prompt)",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="log out an existing session for the device before signing in",
    )
    parser.add_argument(
        "--status",
        nargs="?",
        const="local",
        metavar="IP",
        help="show the portal's view of a session and exit (no credentials needed)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.ac_id is not None and not args.ac_id.isdigit():
        parser.error("--ac-id must be a number")

    if args.status:
        ip = detect_ip() if args.status == "local" else args.status
        show_status(info(ip), ip)
        return 0

    email = (
        args.email or os.environ.get("UCAS_PORTAL_EMAIL") or ask("Email", validate=validate_email)
    )
    password = os.environ.get("UCAS_PORTAL_PASSWORD") or ask("Password", secret=True)
    local_ip = detect_ip()
    ip = args.ip or ask("Server IP", default=local_ip, validate=validate_ip)

    ac_id = args.ac_id or ask(
        "Ac ID (NAS of the device's subnet)",
        validate=validate_ac_id,
    )

    online = show_status(info(ip), ip)
    if online and not args.fresh:
        print("already online; use --fresh to re-login")
        return 0
    if online and args.fresh:
        result = logout(email, ac_id, ip)
        print("logout:", json.dumps(result, ensure_ascii=False))
        if result.get("error") != "ok":
            # The stale session may live on another NAS id; the portal's own
            # logout tries the other stack first, we simply try the default.
            result = logout(email, ac_id, ip)
            print("logout:", json.dumps(result, ensure_ascii=False))

    result = login(email, password, ac_id, ip)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    error = result.get("error")
    if error == "ip_already_online_error":
        print("the device is already logged in; retry with --fresh")
        return 1
    if error != "ok":
        return 1

    print()
    show_status(info(ip), ip)
    _device_hints(ip, local_ip)
    return 0


if __name__ == "__main__":
    sys.exit(main())
