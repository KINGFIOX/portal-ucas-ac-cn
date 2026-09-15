"""Interactive command-line entry point."""
from __future__ import annotations

import json

from .api import login
from .net import detect_ip
from .prompt import ask, validate_email, validate_ip


def show(data: dict) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main() -> int:
    email = ask("Email", validate=validate_email)
    password = ask("Password", secret=True)
    ip = ask("Server IP", default=detect_ip(), validate=validate_ip)

    print()
    result = login(email, password, ip)
    show(result)
    error = result.get("error")
    return 0 if error in {"ok", "ip_already_online_error"} else 1
