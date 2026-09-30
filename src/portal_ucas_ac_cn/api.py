"""Thin client for the Srun portal CGI endpoints.

The portal binds a session to the IP it sees, not to the account that created
it. Callers can therefore target another device by passing its address as
``ip``.

A more subtle rule (the reason headless devices used to end up "online but
unable to reach the IPv4 internet"): the portal hands the session to the NAS
named by ``ac_id``, and each campus subnet is served by its own NAS. The
correct ``ac_id`` for a device is the one the portal's entry redirect
(``/index_1.html``) reports **for a request coming from that device**. A
session created with any other ``ac_id`` shows up as online in
``rad_user_info`` with ``bytes_in == bytes_out == 0`` while the device's
actual gateway never lets its traffic through.

Transport note: the portal's TLS frontend drops a large share of *fresh*
handshakes. A ClientHello is frequently answered with an EOF (or just silence)
after ~5s --- ``SSLEOFError: UNEXPECTED_EOF_WHILE_READING`` / ``Connection
reset by peer`` --- while a handshake that completes stays healthy for many
keep-alive requests. Retrying each individual request therefore both wastes
time (every failure costs ~5s) and occasionally gives up too early. Instead we
retry only the *connect* until it sticks and then reuse that one socket for
the handful of calls a login needs.
"""

from __future__ import annotations

import http.client
import json
import random
import ssl
import time
import urllib.parse

from .srun import hmac_md5, sha1_hex, srun_b64, xencode

HOST = "portal.ucas.ac.cn"
PORTAL = f"https://{HOST}"
# NAS id observed for some wired subnets; only a fallback prompt default.
N = "200"
TYPE = "1"
UA = "Mozilla/5.0 (X11; Linux x86_64) ucas-srun"

# Fresh-handshake success rate fluctuates around 50%, so a handful of tries
# drives the chance of total failure below 0.1%. A dropped handshake is
# answered with an EOF after ~5s, so the connect timeout doubles as a cap on
# how long a doomed attempt can stall us. Reads get a looser budget: a slow
# ``srun_portal`` reply must not look like a dropped connection.
_CONNECT_RETRIES = 12
_CONNECT_TIMEOUT = 5.0
_READ_TIMEOUT = 20.0

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class PortalError(RuntimeError):
    """The portal could not be reached after exhausting the retries."""


def _pause() -> None:
    # Jitter keeps retries from marching in lockstep with the drop pattern.
    time.sleep(0.2 + random.random() * 0.5)


class _Session:
    """A keep-alive HTTPS connection to the portal, reconnected on demand."""

    def __init__(self, host: str = HOST) -> None:
        self._host = host
        self._conn: http.client.HTTPSConnection | None = None

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None

    def _connect(self) -> http.client.HTTPSConnection:
        last: Exception | None = None
        for _ in range(_CONNECT_RETRIES):
            self.close()
            conn = http.client.HTTPSConnection(
                self._host, 443, timeout=_CONNECT_TIMEOUT, context=_CTX
            )
            try:
                conn.connect()
            except (OSError, http.client.HTTPException) as exc:
                last = exc
                _pause()
                continue
            if conn.sock is not None:
                conn.sock.settimeout(_READ_TIMEOUT)
            self._conn = conn
            return conn
        raise PortalError(f"portal unreachable after {_CONNECT_RETRIES} tries: {last!r}")

    def get(self, path: str, params: dict) -> str:
        query = urllib.parse.urlencode(params)
        last: Exception | None = None
        for _ in range(_CONNECT_RETRIES):
            conn = self._conn or self._connect()
            try:
                conn.request("GET", f"{path}?{query}", headers={"User-Agent": UA})
                response = conn.getresponse()
                body = response.read()
            except (OSError, http.client.HTTPException) as exc:
                # The reused socket went away (idle keep-alive timeout, or the
                # frontend dropped it). Drop it and build a new one.
                last = exc
                self.close()
                _pause()
                continue
            if response.status != 200:
                last = PortalError(f"HTTP {response.status} from {path}")
                self.close()
                _pause()
                continue
            if response.will_close:
                self.close()
            return body.decode("utf-8", "replace")
        raise PortalError(f"portal unreachable after {_CONNECT_RETRIES} tries: {last!r}")


_SESSION = _Session()


def api(path: str, **params) -> dict:
    params.setdefault("callback", "cb")
    params.setdefault("_", int(time.time() * 1000))
    text = _SESSION.get(path, params)
    if text.startswith("cb(") and text.endswith(")"):
        text = text[3:-1]
    return json.loads(text)


def info(ip: str) -> dict:
    """Return the portal's view of a session (defaults to this host)."""
    return api("/cgi-bin/rad_user_info", **({"ip": ip} if ip else {}))


def login(username: str, password: str, ac_id: str, ip: str) -> dict:
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
            "acid": ac_id,
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
        + ac_id
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
        ac_id=ac_id,
        ip=use_ip,
        n=N,
        type=TYPE,
    )


def logout(username: str, ac_id: str, ip: str) -> dict:
    """End a password session (the normal logout the web portal performs)."""
    return api(
        "/cgi-bin/srun_portal",
        action="logout",
        username=username,
        **({"ip": ip} if ip else {}),
        ac_id=ac_id,
    )


def unbind_mac_auth(username: str, ip: str) -> dict:
    """Detach a MAC-auth (passwordless) binding, as the portal's logout does."""
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
