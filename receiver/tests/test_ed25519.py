# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""RFC 8032 conformance for the signature check activation rests on.

app/ed25519.py is arithmetic written out rather than a library call, and
the reason that is acceptable is this file. Two things are established
here. The RFC's own vectors verify, which says the implementation is
Ed25519 and not something that merely self-agrees. And the forgeries a
lax verifier accepts are refused: a flipped bit anywhere, a point that is
not on the curve, and a scalar at or above the group order - the last of
which is the one a hand-written verifier usually misses, because ignoring
it makes every signature accept in a second form.
"""

import binascii

import pytest

from app.ed25519 import verify
from tests.ed25519_signer import public_key, sign

h = binascii.unhexlify

# RFC 8032, section 7.1: (secret seed, message, signature). The public key
# is derived rather than pasted, so the vector tests key derivation too.
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
     "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
     "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed,message,signature", VECTORS)
def test_the_rfc_vectors_verify(seed, message, signature):
    pub = public_key(h(seed))
    assert verify(pub, h(message), h(signature))
    # And this suite's signer produces the RFC's signature from the RFC's
    # seed, so a later "both sides agree" result means something.
    assert sign(h(seed), h(message)) == h(signature)


def test_the_wrong_key_does_not_verify():
    pub_a, pub_b = public_key(b"a" * 32), public_key(b"b" * 32)
    msg = b"an activation key's claims"
    assert verify(pub_a, msg, sign(b"a" * 32, msg))
    assert not verify(pub_b, msg, sign(b"a" * 32, msg))


def test_one_flipped_bit_anywhere_is_refused():
    seed = b"s" * 32
    pub, msg = public_key(seed), b'{"v":1,"org":"Acme"}'
    sig = sign(seed, msg)
    assert verify(pub, msg, sig)
    for i in (0, 31, 32, 63):
        broken = bytearray(sig)
        broken[i] ^= 1
        assert not verify(pub, msg, bytes(broken))
    for i in (0, 5, len(msg) - 1):
        broken = bytearray(msg)
        broken[i] ^= 1
        assert not verify(pub, bytes(broken), sig)


def test_a_scalar_at_or_above_the_group_order_is_refused():
    """Malleability: s and s + L are the same signature to a verifier that
    forgets to check the bound, which turns one signature into infinitely
    many valid encodings."""
    seed = b"s" * 32
    pub, msg = public_key(seed), b"claims"
    sig = sign(seed, msg)
    order = 2 ** 252 + 27742317777372353535851937790883648493
    s = int.from_bytes(sig[32:], "little")
    slid = sig[:32] + int.to_bytes(s + order, 32, "little")
    assert verify(pub, msg, sig)
    assert not verify(pub, msg, slid)


def test_bytes_that_are_not_a_point_are_refused_rather_than_raising():
    seed = b"s" * 32
    msg = b"claims"
    sig = sign(seed, msg)
    # y = p - 1 has no matching x; so does an all-ones encoding.
    assert not verify(b"\xff" * 32, msg, sig)
    assert not verify(public_key(seed), msg, b"\xff" * 64)


@pytest.mark.parametrize("pub,sig", [
    (b"", b"\x00" * 64),
    (b"\x00" * 31, b"\x00" * 64),
    (b"\x00" * 32, b""),
    (b"\x00" * 32, b"\x00" * 63),
])
def test_wrong_lengths_are_false_not_an_exception(pub, sig):
    assert verify(pub, b"claims", sig) is False
