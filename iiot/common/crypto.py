from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_CURVE = ec.SECP256R1()
_ECDSA = ec.ECDSA(hashes.SHA256())


def gen_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    sk = ec.generate_private_key(_CURVE)
    pk = sk.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return sk, pk.hex()


def sign(sk: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    return sk.sign(data, _ECDSA).hex()


def verify(pk_hex: str, data: bytes, sig_hex: str) -> bool:
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, bytes.fromhex(pk_hex))
        pub.verify(bytes.fromhex(sig_hex), data, _ECDSA)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sha256_hex(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest()


def make_did(pk_hex: str) -> str:
    return "did:iiot:" + hashlib.sha256(bytes.fromhex(pk_hex)).hexdigest()[:32]


def make_leaf(did: str, pk_hex: str) -> str:
    return sha256_hex(did.encode(), bytes.fromhex(pk_hex))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def b64u_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
