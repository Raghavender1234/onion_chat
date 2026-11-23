"""Cryptographic primitives for OnionChat.

Provides:
- Ed25519 identity signing & verification
- X25519 ephemeral ECDH + HKDF-SHA256 + ChaCha20-Poly1305 E2EE packets
- Local vault encryption with PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305
- Human-readable safety fingerprints
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HKDF_INFO = b"onionchat-p2p-v1"
VAULT_KDF_ITERATIONS = 310_000


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def generate_identity_keys() -> Dict[str, str]:
    """Generate a fresh Ed25519 signing keypair and X25519 encryption keypair."""
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()

    return {
        "ed_priv": b64e(
            ed_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
        "ed_pub": b64e(
            ed_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
        "x_priv": b64e(
            x_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
        "x_pub": b64e(
            x_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    }


def compute_fingerprint(ed_pub_b64: str, x_pub_b64: str) -> str:
    """Return a short human-readable safety number from public keys."""
    digest = hashlib.sha256(b64d(ed_pub_b64) + b64d(x_pub_b64)).digest()
    groups = []
    for i in range(0, 12, 2):
        val = int.from_bytes(digest[i : i + 2], "big") % 100000
        groups.append(f"{val:05d}")
    return " ".join(groups)


def sign_payload(ed_priv_b64: str, payload_bytes: bytes) -> str:
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64d(ed_priv_b64))
    return b64e(priv.sign(payload_bytes))


def verify_signature(ed_pub_b64: str, payload_bytes: bytes, sig_b64: str) -> bool:
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(b64d(ed_pub_b64))
        pub.verify(b64d(sig_b64), payload_bytes)
        return True
    except Exception:
        return False


def encrypt_p2p_packet(
    sender_onion: str,
    sender_ed_priv_b64: str,
    sender_ed_pub_b64: str,
    recipient_x_pub_b64: str,
    inner_payload: Dict[str, Any],
) -> Dict[str, str]:
    """Sign inner_payload with sender's Ed25519 key and encrypt to recipient's X25519 key."""
    plaintext_obj = {
        "sender_onion": sender_onion,
        "sender_ed_pub": sender_ed_pub_b64,
        "payload": inner_payload,
    }
    plaintext_bytes = json.dumps(plaintext_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = sign_payload(sender_ed_priv_b64, plaintext_bytes)

    signed_envelope = json.dumps(
        {"data": b64e(plaintext_bytes), "sig": signature},
        separators=(",", ":"),
    ).encode("utf-8")

    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(b64d(recipient_x_pub_b64))
    shared_secret = eph_priv.exchange(recipient_pub)

    sym_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub_bytes,
        info=HKDF_INFO,
    ).derive(shared_secret)

    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(sym_key).encrypt(nonce, signed_envelope, eph_pub_bytes)

    return {
        "v": "1",
        "eph": b64e(eph_pub_bytes),
        "nonce": b64e(nonce),
        "ct": b64e(ciphertext),
    }


def decrypt_p2p_packet(
    recipient_x_priv_b64: str,
    packet: Dict[str, Any],
) -> Tuple[str, str, Dict[str, Any]]:
    """Decrypt a P2P packet and verify its Ed25519 signature.

    Returns (sender_onion, sender_ed_pub_b64, inner_payload).
    Raises ValueError on decryption or signature failure.
    """
    try:
        eph_pub_bytes = b64d(packet["eph"])
        nonce = b64d(packet["nonce"])
        ct = b64d(packet["ct"])
    except Exception as exc:
        raise ValueError("Malformed encrypted packet") from exc

    x_priv = x25519.X25519PrivateKey.from_private_bytes(b64d(recipient_x_priv_b64))
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared_secret = x_priv.exchange(eph_pub)

    sym_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub_bytes,
        info=HKDF_INFO,
    ).derive(shared_secret)

    try:
        signed_bytes = ChaCha20Poly1305(sym_key).decrypt(nonce, ct, eph_pub_bytes)
        signed_obj = json.loads(signed_bytes.decode("utf-8"))
        plaintext_bytes = b64d(signed_obj["data"])
        sig_b64 = signed_obj["sig"]
        plaintext_obj = json.loads(plaintext_bytes.decode("utf-8"))
        sender_onion = plaintext_obj["sender_onion"]
        sender_ed_pub = plaintext_obj["sender_ed_pub"]
        payload = plaintext_obj["payload"]
    except Exception as exc:
        raise ValueError("Packet decryption failed") from exc

    if not verify_signature(sender_ed_pub, plaintext_bytes, sig_b64):
        raise ValueError("Invalid Ed25519 signature")

    return sender_onion, sender_ed_pub, payload


def _derive_vault_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=VAULT_KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_vault(data: Dict[str, Any], passphrase: str) -> bytes:
    salt = os.urandom(16)
    key = _derive_vault_key(passphrase, salt)
    nonce = os.urandom(12)
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    ct = ChaCha20Poly1305(key).encrypt(nonce, raw, b"onionchat-vault-v1")
    envelope = {
        "v": 1,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ct": b64e(ct),
    }
    return json.dumps(envelope).encode("utf-8")


def decrypt_vault(blob: bytes, passphrase: str) -> Dict[str, Any]:
    envelope = json.loads(blob.decode("utf-8"))
    salt = b64d(envelope["salt"])
    nonce = b64d(envelope["nonce"])
    ct = b64d(envelope["ct"])
    key = _derive_vault_key(passphrase, salt)
    raw = ChaCha20Poly1305(key).decrypt(nonce, ct, b"onionchat-vault-v1")
    return json.loads(raw.decode("utf-8"))
