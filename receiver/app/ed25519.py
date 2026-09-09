# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Ed25519 signature verification, RFC 8032, and nothing else.

An activation key is checked offline: the receiver holds the publisher's
public key and never asks anyone whether a key is good. That promise is the
whole point - a licence that phones home is a licence that stops working
when the vendor does - so the check has to be something the container can
always do, on any network, forever.

Why the arithmetic is here rather than a dependency: the only operation
needed is verify, over public data, in two components whose entire
dependency list is four packages. Pulling in a compiled crypto library to
do one signature check would add a build toolchain to both images for a
routine that fits on a page. There is no private key in this process and
none in this repository, so the usual reason to insist on a hardened
implementation - secret-dependent timing - does not arise: everything below
touches only a public key, a public message and a public signature.

What that trade does cost is the assurance a reviewed library carries, so
it is bought back in the tests: test_ed25519.py runs the RFC 8032 test
vectors and the cases a naive verifier gets wrong (a non-canonical scalar,
a point off the curve, a flipped bit in each field).

Not constant time, and deliberately not claimed to be.
"""

import hashlib

# The curve, as RFC 8032 states it.
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int):
    """The x that goes with a compressed y, or None if there is none.

    Returning None rather than raising matters: an attacker chooses the
    bytes, so "this is not a point on the curve" is an ordinary answer the
    caller turns into false, not an exceptional one.
    """
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


# Extended homogeneous coordinates (X, Y, Z, T): x = X/Z, y = Y/Z, xy = T/Z.
# Addition is unified - the same formula for doubling - so there is no
# special case to get wrong on a chosen input.
def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    e = 2 * p[2] * q[2] % _P
    f, g, h, i = b - a, e - c, e + c, b + a
    return (f * g % _P, h * i % _P, g * h % _P, f * i % _P)


def _mul(s: int, p):
    r = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            r = _add(r, p)
        p = _add(p, p)
        s >>= 1
    return r


def _equal(p, q) -> bool:
    return ((p[0] * q[2] - q[0] * p[2]) % _P == 0
            and (p[1] * q[2] - q[1] * p[2]) % _P == 0)


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _decompress(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True only if signature is this key's signature over this message.

    Every malformed input answers False rather than raising, because all
    three arguments come from outside and a signature check that can throw
    is a signature check somebody wraps in a bare except.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    r_bytes = signature[:32]
    r = _decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    # A scalar at or above the group order is a second encoding of a
    # signature that already verifies. Rejecting it is what stops one
    # signature having more than one valid form.
    if s >= _Q:
        return False
    h = int.from_bytes(
        hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))
