# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""An Ed25519 signer, for tests only.

The receiver verifies and never signs, so app/ed25519.py has no signing in
it and this does not belong beside it: shipping a signer in the component
that checks signatures invites the question of what it is for. Tests need
to issue keys of their own, though - a suite that can only check one
hard-coded key cannot test a forgery - so the other half of RFC 8032 lives
here, in the tests, where it can never reach an image.

Reused by test_ed25519.py to reproduce the RFC's own vectors from their
seeds, which is what says these twenty lines are the real algorithm rather
than something that merely agrees with app/ed25519.py.
"""

import hashlib

from app.ed25519 import _G, _P, _Q, _mul


def _compress(point) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, _P - 2, _P)
    x, y = x * zinv % _P, y * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _expand(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress(_mul(a, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _Q
    big_r = _compress(_mul(r, _G))
    h = int.from_bytes(
        hashlib.sha512(big_r + pub + message).digest(), "little") % _Q
    return big_r + int.to_bytes((r + h * a) % _Q, 32, "little")
