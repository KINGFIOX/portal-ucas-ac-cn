"""Thin client for the Srun portal CGI endpoints.

The portal binds a session to the IP it sees, not to the account that created
it. Callers can therefore target another device by passing its address as
``ip``.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.parse
import urllib.request

from .srun import hmac_md5, sha1_hex, srun_b64, xencode

PORTAL = "https://portal.ucas.ac.cn"
AC_ID = "1"
N = "200"
TYPE = "1"
UA = "Mozilla/5.0 (X11; Linux x86_64) ucas-srun"
CTX = ssl._create_unverified_context()


def api(path: str, **params) -> dict:
    params.setdefault("callback", "cb")
    params.setdefault("_", int(time.time() * 1000))
    url = PORTAL + path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15, context=CTX) as resp:
        text = resp.read().decode("utf-8", "replace")
    if text.startswith("cb(") and text.endswith(")"):
        text = text[3:-1]
    return json.loads(text)


def info(ip: str | None = None) -> dict:
    """Return the portal's view of a session (defaults to this host)."""
    return api("/cgi-bin/rad_user_info", **({"ip": ip} if ip else {}))


def login(username: str, password: str, ip: str | None = None) -> dict:
    params = {"username": username}
    if ip:
        params["ip"] = ip
    challenge = api("/cgi-bin/get_challenge", **params)
    token = challenge.get("challenge")
    if not token:
        return challenge
    # Srun reports client_ip (the host making the request) and online_ip
    # (the address we asked for). Prefer the latter.
    use_ip = challenge.get("online_ip") or challenge.get("client_ip") or ip or ""
    digest = hmac_md5(password, token)
    payload = json.dumps(
        {
            "username": username,
            "password": password,
            "ip": use_ip,
            "acid": AC_ID,
            "enc_ver": "srun_bx1",
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    encoded = "{SRBX1}" + srun_b64(xencode(payload, token))
    checksum = sha1_hex(
        token
        + username
        + token
        + digest
        + token
        + AC_ID
        + token
        + use_ip
        + token
        + N
        + token
        + TYPE
        + token
        + encoded
    )
    return api(
        "/cgi-bin/srun_portal",
        action="login",
        username=username,
        password="{MD5}" + digest,
        os="Linux",
        name="Linux",
        double_stack="0",
        chksum=checksum,
        info=encoded,
        ac_id=AC_ID,
        ip=use_ip,
        n=N,
        type=TYPE,
    )


def logout(username: str, ip: str) -> dict:
    now = str(int(time.time()))
    sign = sha1_hex(now + username + ip + "0" + now)
    return api(
        "/cgi-bin/rad_user_dm",
        ip=ip,
        username=username,
        time=now,
        unbind="0",
        sign=sign,
    )


def current_username() -> str | None:
    data = info()
    if data.get("error") == "ok":
        return data.get("user_name")
    return None
