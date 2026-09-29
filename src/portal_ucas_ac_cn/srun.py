"""Srun portal payload encoding.

The portal wants the login payload encrypted with a modified XXTEA and then
base64-encoded using a shuffled alphabet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

ALPHA_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ALPHA_SRUN = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
B64_TRANS = str.maketrans(ALPHA_STD, ALPHA_SRUN)


def hmac_md5(password: str, token: str) -> str:
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def srun_b64(data: bytes) -> str:
    return base64.b64encode(data).decode().translate(B64_TRANS)


def _ords(msg: str, idx: int) -> int:
    return ord(msg[idx]) if idx < len(msg) else 0


def _s(msg: str, postfix: bool) -> list[int]:
    out = []
    for i in range(0, len(msg), 4):
        out.append(
            _ords(msg, i)
            | _ords(msg, i + 1) << 8
            | _ords(msg, i + 2) << 16
            | _ords(msg, i + 3) << 24
        )
    if postfix:
        out.append(len(msg))
    return out


def _l(arr: list[int], postfix: bool) -> bytes:
    n = len(arr)
    count = (n - 1) * 4
    if postfix:
        org = arr[-1]
        if not (count - 3 <= org <= count):
            return b""
        count = org
    raw = bytearray()
    for x in arr:
        raw.extend((x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF))
    return bytes(raw[:count] if postfix else raw)


def xencode(msg: str, key: str) -> bytes:
    if not msg:
        return b""

    def u32(x: int) -> int:
        return x & 0xFFFFFFFF

    v = _s(msg, True)
    k = _s(key, False)
    if len(k) < 4:
        k.extend([0] * (4 - len(k)))
    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = u32(0x86014019 | 0x183639A0)
    q = 6 + 52 // (n + 1)
    d = 0
    while q > 0:
        q -= 1
        d = u32(d + c)
        e = (d >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = u32(
                ((z >> 5) ^ ((y << 2) & 0xFFFFFFFF))
                + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF) ^ (d ^ y))
                + (k[(p & 3) ^ e] ^ z)
            )
            v[p] = u32(v[p] + m)
            z = v[p]
        y = v[0]
        m = u32(
            ((z >> 5) ^ ((y << 2) & 0xFFFFFFFF))
            + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF) ^ (d ^ y))
            + (k[(n & 3) ^ e] ^ z)
        )
        v[n] = u32(v[n] + m)
        z = v[n]
    return _l(v, False)
