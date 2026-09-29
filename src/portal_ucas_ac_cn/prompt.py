"""Plain interactive prompts, in the FreeBSD adduser style.

A value shown in ``[]`` is the default and is used when Enter is pressed.
"""

from __future__ import annotations

import getpass
import ipaddress
from collections.abc import Callable

Validator = Callable[[str], "str | None"]


def ask(
    label: str,
    default: str | None = None,
    secret: bool = False,
    validate: Validator | None = None,
) -> str:
    while True:
        hint = f" [{default}]" if default else ""
        try:
            if secret:
                value = getpass.getpass(f"{label}{hint}: ")
            else:
                value = input(f"{label}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(1) from None
        if not value and default is not None:
            value = default
        if not value:
            print("  A value is required.")
            continue
        if validate:
            error = validate(value)
            if error:
                print(f"  {error}")
                continue
        return value


def validate_email(value: str) -> str | None:
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        return f"'{value}' does not look like an email address."
    return None


def validate_ip(value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return f"'{value}' is not a valid IP address."
    return None


def validate_ac_id(value: str) -> str | None:
    if not value.isdigit():
        return f"'{value}' is not a NAS id; expected a plain number (e.g. 12)."
    return None
