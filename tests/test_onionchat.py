"""Tests for OnionChat crypto, QR generation/decoding, vault storage, and P2P packet flow."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.crypto import (
    compute_fingerprint,
    decrypt_p2p_packet,
    decrypt_vault,
    encrypt_p2p_packet,
    encrypt_vault,
    generate_identity_keys,
)
from src.p2p_node import OnionChatNode
from src.qr_utils import (
    build_invite_uri,
    decode_qr_from_bytes,
    generate_invite_card_png,
    generate_qr_png,
    parse_invite_uri,
)
from src.storage import VaultStore


def test_e2ee_packet_roundtrip() -> None:
    alice = generate_identity_keys()
    bob = generate_identity_keys()
    alice_onion = "a" * 56 + ".onion"

    pkt = encrypt_p2p_packet(
        sender_onion=alice_onion,
        sender_ed_priv_b64=alice["ed_priv"],
        sender_ed_pub_b64=alice["ed_pub"],
        recipient_x_pub_b64=bob["x_pub"],
        inner_payload={"type": "chat", "id": "m1", "text": "Hello Bob!"},
    )

    sender_onion, sender_ed_pub, payload = decrypt_p2p_packet(bob["x_priv"], pkt)
    assert sender_onion == alice_onion
    assert sender_ed_pub == alice["ed_pub"]
    assert payload["text"] == "Hello Bob!"

    # Wrong recipient key must fail
    eve = generate_identity_keys()
    try:
        decrypt_p2p_packet(eve["x_priv"], pkt)
        raise AssertionError("Expected decryption failure for wrong key")
    except ValueError:
        pass


def test_qr_roundtrip_and_card() -> None:
    keys = generate_identity_keys()
    onion = "b" * 56 + ".onion"
    uri = build_invite_uri("Alice", "alice", onion, keys["ed_pub"], keys["x_pub"])

    # Raw QR PNG
    qr_png = generate_qr_png(uri)
    decoded = decode_qr_from_bytes(qr_png)
    assert decoded == uri
    parsed = parse_invite_uri(decoded)
    assert parsed["display_name"] == "Alice"
    assert parsed["username"] == "alice"
    assert parsed["onion"] == onion
    assert parsed["fingerprint"] == compute_fingerprint(keys["ed_pub"], keys["x_pub"])

    # Branded QR Card PNG
    card_png = generate_invite_card_png("Alice", "alice", onion, keys["ed_pub"], keys["x_pub"])
    decoded_card = decode_qr_from_bytes(card_png)
    assert decoded_card == uri


def test_vault_encryption_and_wipe() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = VaultStore(base_dir=Path(tmp))
        store.init_vault_mode(passphrase="super-secret-pin")
        store.set_profile({"display_name": "Alice", "username": "alice", "onion": "x" * 56 + ".onion"})
        assert store.has_existing_vault()
        assert store.needs_passphrase()

        store2 = VaultStore(base_dir=Path(tmp))
        assert not store2.unlock_existing(passphrase="wrong-pin")
        assert store2.unlock_existing(passphrase="super-secret-pin")
        assert store2.profile is not None
        assert store2.profile["username"] == "alice"

        store2.wipe_all()
        assert not store2.has_existing_vault()

        # Convenience mode (no passphrase) uses DPAPI on Windows
        store3 = VaultStore(base_dir=Path(tmp))
        store3.init_vault_mode(passphrase=None)
        store3.set_profile({"display_name": "Bob", "username": "bob", "onion": "y" * 56 + ".onion"})
        key_text = store3.key_path.read_text(encoding="utf-8")
        assert key_text.startswith("dpapi:")
        store4 = VaultStore(base_dir=Path(tmp))
        assert store4.unlock_existing(passphrase=None)
        assert store4.profile is not None and store4.profile["username"] == "bob"
        store4.wipe_all()


async def _run_p2p_handshake_and_chat() -> None:
    with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
        ui_dir = ROOT / "ui"
        node_a = OnionChatNode(ui_dir=ui_dir, profile_dir=Path(tmp1))
        node_b = OnionChatNode(ui_dir=ui_dir, profile_dir=Path(tmp2))
        await node_a.start()
        await node_b.start()
        try:
            # Verify index.html injects the token properly and /api/state works (no 403)
            async with aiohttp.ClientSession() as s:
                async with s.get(f"http://127.0.0.1:{node_a.http_port}/") as resp:
                    assert resp.status == 200
                    html_text = await resp.text()
                    assert f'window.__ONIONCHAT_TOKEN__ = "{node_a.local_token}"' in html_text
                async with s.get(
                    f"http://127.0.0.1:{node_a.http_port}/api/state",
                    headers={"X-Local-Token": node_a.local_token},
                ) as resp:
                    assert resp.status == 200

            keys_a = generate_identity_keys()
            keys_b = generate_identity_keys()
            onion_a = "a" * 56 + ".onion"
            onion_b = "b" * 56 + ".onion"

            node_a.store.init_ghost_mode()
            node_b.store.init_ghost_mode()
            node_a.store.set_profile({"display_name": "Alice", "username": "alice", "onion": onion_a, **keys_a})
            node_b.store.set_profile({"display_name": "Bob", "username": "bob", "onion": onion_b, **keys_b})

            # Spoofed handshake identity binding must be rejected (403)
            eve = generate_identity_keys()
            spoof_pkt = encrypt_p2p_packet(
                onion_a,
                keys_a["ed_priv"],
                keys_a["ed_pub"],
                keys_b["x_pub"],
                {
                    "type": "handshake",
                    "action": "request",
                    "display_name": "Eve",
                    "username": "eve",
                    "onion": onion_a,
                    "ed_pub": eve["ed_pub"],
                    "x_pub": eve["x_pub"],
                },
            )
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{node_b.http_port}/p2p/packet", json=spoof_pkt) as resp:
                    assert resp.status == 403

            # Simulate Alice sending a valid handshake packet directly to Bob's local P2P endpoint
            pkt = encrypt_p2p_packet(
                onion_a,
                keys_a["ed_priv"],
                keys_a["ed_pub"],
                keys_b["x_pub"],
                {
                    "type": "handshake",
                    "action": "request",
                    "display_name": "Alice",
                    "username": "alice",
                    "onion": onion_a,
                    "ed_pub": keys_a["ed_pub"],
                    "x_pub": keys_a["x_pub"],
                },
            )
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{node_b.http_port}/p2p/packet", json=pkt) as resp:
                    assert resp.status == 200

            assert onion_a in node_b.store.friends
            assert node_b.store.friends[onion_a]["status"] == "pending_in"

            # Bob accepts Alice
            node_b.store.upsert_friend(onion_a, {"status": "accepted"})
            node_a.store.upsert_friend(
                onion_b,
                {
                    "display_name": "Bob",
                    "username": "bob",
                    "onion": onion_b,
                    "ed_pub": keys_b["ed_pub"],
                    "x_pub": keys_b["x_pub"],
                    "fingerprint": compute_fingerprint(keys_b["ed_pub"], keys_b["x_pub"]),
                    "status": "accepted",
                    "unread": 0,
                },
            )

            # Alice sends encrypted chat message to Bob
            chat_pkt = encrypt_p2p_packet(
                onion_a,
                keys_a["ed_priv"],
                keys_a["ed_pub"],
                keys_b["x_pub"],
                {"type": "chat", "id": "msg-1", "text": "Secret over Tor!", "timestamp": 123456.0},
            )
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{node_b.http_port}/p2p/packet", json=chat_pkt) as resp:
                    assert resp.status == 200

            msgs = node_b.store.messages[onion_a]
            assert len(msgs) == 1
            assert msgs[0]["text"] == "Secret over Tor!"
            assert node_b.store.friends[onion_a]["unread"] == 1

            # Test out-of-order + duplicate multi-chunk media transfer with SHA-256 verification
            import base64
            import hashlib

            part1 = b"A" * 1024
            part2 = b"B" * 512
            expected_sha = hashlib.sha256(part1 + part2).hexdigest()
            chunks = [(1, part2), (0, part1), (0, part1)]  # out-of-order + duplicate
            for idx, raw in chunks:
                m_pkt = encrypt_p2p_packet(
                    onion_a,
                    keys_a["ed_priv"],
                    keys_a["ed_pub"],
                    keys_b["x_pub"],
                    {
                        "type": "media_chunk",
                        "media_id": "vid-4k-1",
                        "name": "vacation_4k.mp4",
                        "mime": "video/mp4",
                        "size": len(part1) + len(part2),
                        "sha256": expected_sha,
                        "caption": "4K clip!",
                        "timestamp": 123457.0,
                        "chunk_index": idx,
                        "total_chunks": 2,
                        "data_b64": base64.b64encode(raw).decode("ascii"),
                    },
                )
                async with aiohttp.ClientSession() as s:
                    async with s.post(f"http://127.0.0.1:{node_b.http_port}/p2p/packet", json=m_pkt) as resp:
                        assert resp.status == 200

            saved_media = node_b.store.media_dir / "vid-4k-1_vacation_4k.mp4"
            assert saved_media.is_file()
            assert saved_media.read_bytes() == part1 + part2
            assert len(node_b.store.messages[onion_a]) == 2

            # Test profile photo update & 24h friends-only story
            avatar_pkt = encrypt_p2p_packet(
                onion_a,
                keys_a["ed_priv"],
                keys_a["ed_pub"],
                keys_b["x_pub"],
                {"type": "profile_update", "display_name": "Alice", "avatar_b64": "data:image/jpeg;base64,AAAA"},
            )
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{node_b.http_port}/p2p/packet", json=avatar_pkt) as resp:
                    assert resp.status == 200
            assert node_b.store.friends[onion_a]["avatar_b64"] == "data:image/jpeg;base64,AAAA"

            import time

            story_pkt = encrypt_p2p_packet(
                onion_a,
                keys_a["ed_priv"],
                keys_a["ed_pub"],
                keys_b["x_pub"],
                {
                    "type": "story",
                    "story": {
                        "id": "story-1",
                        "author_name": "Alice",
                        "author_username": "alice",
                        "text": "Sunset!",
                        "bg_color": "#005c4b",
                        "created_at": time.time(),
                        "expires_at": time.time() + 86400,
                    },
                },
            )
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{node_b.http_port}/p2p/packet", json=story_pkt) as resp:
                    assert resp.status == 200
            assert len(node_b.store.stories) == 1
            assert node_b.store.stories[0]["text"] == "Sunset!"

            # Test soft delete + restore on Bob's side
            trashed = node_b.store.soft_delete_chat(onion_a)
            assert trashed is not None
            assert len(node_b.store.messages[onion_a]) == 0
            assert node_b.store.restore_trash_item(trashed["id"])
            assert len(node_b.store.messages[onion_a]) == 2

            # Test encrypted .hushbackup export & import
            backup_blob = node_b.store.export_encrypted_backup("my-backup-pw")
            with tempfile.TemporaryDirectory() as tmp_restore:
                restored_store = VaultStore(base_dir=Path(tmp_restore))
                assert not restored_store.import_encrypted_backup(backup_blob, "wrong-pw")
                assert restored_store.import_encrypted_backup(backup_blob, "my-backup-pw")
                assert len(restored_store.messages[onion_a]) == 2
                assert (restored_store.media_dir / "vid-4k-1_vacation_4k.mp4").is_file()

            # Test remote shred_chat: Alice shreds, Bob's chat & media are wiped permanently
            shred_pkt = encrypt_p2p_packet(
                onion_a,
                keys_a["ed_priv"],
                keys_a["ed_pub"],
                keys_b["x_pub"],
                {"type": "shred_chat"},
            )
            async with aiohttp.ClientSession() as s:
                async with s.post(f"http://127.0.0.1:{node_b.http_port}/p2p/packet", json=shred_pkt) as resp:
                    assert resp.status == 200
            assert len(node_b.store.messages[onion_a]) == 0
            assert not saved_media.exists()
        finally:
            await node_a.stop()
            await node_b.stop()


def test_p2p_handshake_and_chat() -> None:
    asyncio.run(_run_p2p_handshake_and_chat())


if __name__ == "__main__":
    test_e2ee_packet_roundtrip()
    test_qr_roundtrip_and_card()
    test_vault_encryption_and_wipe()
    test_p2p_handshake_and_chat()
    print("All OnionChat tests passed!")
