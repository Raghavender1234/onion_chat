"""P2P Tor node and local UI API server for OnionChat."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiohttp
from aiohttp import web
from aiohttp_socks import ProxyConnector

from .crypto import (
    compute_fingerprint,
    decrypt_p2p_packet,
    encrypt_p2p_packet,
    generate_identity_keys,
)
from .qr_utils import (
    build_invite_uri,
    decode_qr_from_bytes,
    generate_invite_card_png,
    generate_qr_png,
    parse_invite_uri,
)
from .storage import VaultStore
from .tor_manager import TorManager, find_free_port


class OnionChatNode:
    """Coordinates the local aiohttp server, Tor hidden service, and P2P messaging."""

    def __init__(self, ui_dir: Path, profile_dir: Optional[Path] = None) -> None:
        self.ui_dir = ui_dir
        self.store = VaultStore(base_dir=profile_dir)
        self.http_port = find_free_port()
        self.local_token = secrets.token_urlsafe(24)
        self.tor: Optional[TorManager] = None

        self.tor_status: str = "Not started"
        self.tor_progress: int = 0
        self.tor_ready: bool = False
        self.tor_error: Optional[str] = None

        self._sse_clients: Set[asyncio.Queue[str]] = set()
        self._bg_tasks: List[asyncio.Task[None]] = []
        self._runner: Optional[web.AppRunner] = None
        self._app = self._build_app()

    def _build_app(self) -> web.Application:
        app = web.Application(client_max_size=1024 * 1024 * 1024)
        # P2P endpoint (reachable via Encrypted P2P Hidden Service)
        app.router.add_post("/p2p/packet", self.handle_p2p_packet)

        # Local UI API endpoints
        app.router.add_get("/api/state", self.handle_get_state)
        app.router.add_get("/api/events", self.handle_sse)
        app.router.add_post("/api/onboard", self.handle_onboard)
        app.router.add_post("/api/unlock", self.handle_unlock)
        app.router.add_get("/api/qr", self.handle_get_qr)
        app.router.add_get("/api/qr/card", self.handle_get_qr_card)
        app.router.add_post("/api/friends/decode-qr", self.handle_decode_qr)
        app.router.add_post("/api/friends/add", self.handle_add_friend)
        app.router.add_post("/api/friends/respond", self.handle_respond_friend)
        app.router.add_post("/api/friends/remove", self.handle_remove_friend)
        app.router.add_post("/api/messages/send", self.handle_send_message)
        app.router.add_post("/api/media/send", self.handle_send_media)
        app.router.add_get("/api/media/{media_id}", self.handle_get_media)
        app.router.add_post("/api/messages/read", self.handle_mark_read)
        app.router.add_post("/api/typing", self.handle_typing)
        app.router.add_post("/api/profile/avatar", self.handle_set_avatar)
        app.router.add_post("/api/stories/add", self.handle_add_story)
        app.router.add_post("/api/stories/view", self.handle_view_story)
        app.router.add_post("/api/chat/delete", self.handle_delete_chat)
        app.router.add_post("/api/trash/restore", self.handle_restore_trash)
        app.router.add_post("/api/trash/empty", self.handle_empty_trash)
        app.router.add_post("/api/backup/export", self.handle_export_backup)
        app.router.add_post("/api/backup/import", self.handle_import_backup)
        app.router.add_post("/api/wipe", self.handle_wipe)

        # Static UI
        app.router.add_get("/", self.handle_index)
        app.router.add_static("/static/", path=str(self.ui_dir), name="static")
        return app

    async def start(self) -> int:
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self.http_port)
        await site.start()
        return self.http_port

    async def stop(self) -> None:
        for t in self._bg_tasks:
            t.cancel()
        self._bg_tasks.clear()
        if self.tor:
            self.tor.stop()
            self.tor = None
        self.store.cleanup_ghost()
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    def _emit(self, event: str, data: Any) -> None:
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        dead = []
        for q in self._sse_clients:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._sse_clients.discard(q)

    def _check_local_auth(self, request: web.Request) -> bool:
        token = request.headers.get("X-Local-Token") or request.query.get("token")
        return token == self.local_token

    async def _start_tor_service(self, tor_dir: Path) -> str:
        self.tor_error = None
        self.tor_ready = False

        def on_progress(msg: str, pct: int) -> None:
            self.tor_status = msg
            self.tor_progress = pct
            self._emit("tor_status", {"status": msg, "progress": pct, "ready": False})

        self.tor = TorManager(tor_data_dir=tor_dir, local_http_port=self.http_port)
        try:
            onion = await self.tor.start(status_cb=on_progress)
            self.tor_ready = True
            self.tor_status = "Encrypted Network Ready"
            self.tor_progress = 100
            self._emit(
                "tor_status",
                {"status": self.tor_status, "progress": 100, "ready": True, "onion": onion},
            )
            self._start_background_workers()
            return onion
        except Exception as exc:
            self.tor_error = str(exc)
            self.tor_status = f"Connection error: {exc}"
            self._emit(
                "tor_status",
                {"status": self.tor_status, "progress": 0, "ready": False, "error": str(exc)},
            )
            raise

    def _start_background_workers(self) -> None:
        if not self._bg_tasks:
            self._bg_tasks.append(asyncio.create_task(self._outbox_worker()))
            self._bg_tasks.append(asyncio.create_task(self._presence_worker()))

    def _public_state(self) -> Dict[str, Any]:
        profile = self.store.profile
        safe_profile = None
        self.store.prune_expired_stories()
        if profile:
            safe_profile = {
                "display_name": profile["display_name"],
                "username": profile["username"],
                "onion": profile["onion"],
                "avatar_b64": profile.get("avatar_b64"),
                "ed_pub": profile["ed_pub"],
                "x_pub": profile["x_pub"],
                "fingerprint": compute_fingerprint(profile["ed_pub"], profile["x_pub"]),
                "invite_uri": build_invite_uri(
                    profile["display_name"],
                    profile["username"],
                    profile["onion"],
                    profile["ed_pub"],
                    profile["x_pub"],
                ),
            }
        return {
            "has_vault": self.store.has_existing_vault(),
            "needs_passphrase": self.store.needs_passphrase(),
            "unlocked": self.store.unlocked,
            "ghost_mode": self.store.ghost_mode,
            "profile": safe_profile,
            "friends": self.store.friends,
            "messages": self.store.messages,
            "stories": self.store.stories,
            "trash": self.store.trash,
            "tor": {
                "ready": self.tor_ready,
                "status": self.tor_status,
                "progress": self.tor_progress,
                "error": self.tor_error,
            },
        }

    # ------------------------------------------------------------------
    # Local UI Handlers
    # ------------------------------------------------------------------

    async def handle_index(self, request: web.Request) -> web.Response:
        html = (self.ui_dir / "index.html").read_text(encoding="utf-8")
        # Inject session token into HTML so only our UI window can call /api/*
        html = html.replace("__LOCAL_SESSION_TOKEN__", self.local_token)
        return web.Response(
            text=html,
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    async def handle_sse(self, request: web.Request) -> web.StreamResponse:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        resp = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await resp.prepare(request)
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=200)
        self._sse_clients.add(q)
        try:
            init_evt = f"event: state\ndata: {json.dumps(self._public_state())}\n\n"
            await resp.write(init_evt.encode("utf-8"))
            while True:
                msg = await q.get()
                await resp.write(msg.encode("utf-8"))
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            self._sse_clients.discard(q)
        return resp

    async def handle_get_state(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        return web.json_response(self._public_state())

    async def handle_onboard(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        display_name = str(body.get("display_name", "")).strip()[:48]
        username = str(body.get("username", "")).strip().lower()[:32]
        username = "".join(ch for ch in username if ch.isalnum() or ch in "._-")
        ghost_mode = bool(body.get("ghost_mode", False))
        passphrase = str(body.get("passphrase", "")).strip() or None

        if not display_name or not username:
            return web.json_response(
                {"error": "Please enter both a display name and username."}, status=400
            )

        if ghost_mode:
            tor_dir = self.store.init_ghost_mode()
        else:
            tor_dir = self.store.init_vault_mode(passphrase=passphrase)

        keys = generate_identity_keys()
        # Start Tor in background or await? Await here or return immediately and stream progress!
        # Let's start Tor and await so the UI gets progress via SSE while showing the Tor bootstrap bar.
        onion = await self._start_tor_service(tor_dir)
        profile = {
            "display_name": display_name,
            "username": username,
            "onion": onion,
            "created_at": time.time(),
            **keys,
        }
        self.store.set_profile(profile)
        self._emit("state", self._public_state())
        return web.json_response(self._public_state())

    async def handle_unlock(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        passphrase = str(body.get("passphrase", "")).strip() or None
        if not self.store.unlock_existing(passphrase=passphrase):
            return web.json_response({"error": "Incorrect passphrase or corrupted vault."}, status=401)
        await self._start_tor_service(self.store.tor_dir)
        self._emit("state", self._public_state())
        return web.json_response(self._public_state())

    async def handle_get_qr(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        p = self.store.profile
        if not p:
            return web.Response(status=404, text="No profile")
        uri = build_invite_uri(p["display_name"], p["username"], p["onion"], p["ed_pub"], p["x_pub"])
        png = generate_qr_png(uri)
        return web.Response(body=png, content_type="image/png")

    async def handle_get_qr_card(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        p = self.store.profile
        if not p:
            return web.Response(status=404, text="No profile")
        png = generate_invite_card_png(
            p["display_name"], p["username"], p["onion"], p["ed_pub"], p["x_pub"]
        )
        headers = {"Content-Disposition": f'attachment; filename="{p["username"]}_hush_qr.png"'}
        return web.Response(body=png, content_type="image/png", headers=headers)

    async def handle_decode_qr(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        reader = await request.multipart()
        field = await reader.next()
        if field is None:
            return web.json_response({"error": "No image file provided."}, status=400)
        img_bytes = await field.read(decode=False)
        decoded = decode_qr_from_bytes(img_bytes)
        if not decoded:
            return web.json_response(
                {"error": "Could not detect a valid QR code in that image."}, status=400
            )
        try:
            invite = parse_invite_uri(decoded)
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response({"invite": invite, "raw": decoded})

    async def handle_add_friend(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        p = self.store.profile
        if not p:
            return web.json_response({"error": "Not onboarded"}, status=400)
        body = await request.json()
        invite_text = str(body.get("invite_uri", "")).strip()
        try:
            invite = parse_invite_uri(invite_text)
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)

        target_onion = invite["onion"]
        if target_onion == p["onion"]:
            return web.json_response({"error": "You cannot add yourself."}, status=400)

        existing = self.store.friends.get(target_onion)
        if existing and existing.get("status") == "accepted":
            return web.json_response({"friend": existing, "already_friend": True})

        # If they already sent us a pending_in request, auto-accept!
        new_status = "accepted" if (existing and existing.get("status") == "pending_in") else "pending_out"
        action = "accept" if new_status == "accepted" else "request"

        friend_rec = {
            "display_name": invite["display_name"],
            "username": invite["username"],
            "onion": target_onion,
            "ed_pub": invite["ed_pub"],
            "x_pub": invite["x_pub"],
            "fingerprint": invite["fingerprint"],
            "status": new_status,
            "online": False,
            "last_seen": None,
            "unread": 0,
        }
        self.store.upsert_friend(target_onion, friend_rec)
        self._emit("friends_updated", self.store.friends)

        # Send handshake packet over Tor (queued if offline)
        handshake_payload = {
            "type": "handshake",
            "action": action,
            "display_name": p["display_name"],
            "username": p["username"],
            "onion": p["onion"],
            "ed_pub": p["ed_pub"],
            "x_pub": p["x_pub"],
        }
        await self._send_or_queue(target_onion, handshake_payload)
        return web.json_response({"friend": friend_rec})

    async def handle_respond_friend(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        p = self.store.profile
        if not p:
            return web.json_response({"error": "Not onboarded"}, status=400)
        body = await request.json()
        onion = str(body.get("onion", "")).strip()
        accept = bool(body.get("accept", True))
        friend = self.store.friends.get(onion)
        if not friend:
            return web.json_response({"error": "Friend request not found"}, status=404)

        if accept:
            self.store.upsert_friend(onion, {"status": "accepted"})
            await self._send_or_queue(
                onion,
                {
                    "type": "handshake",
                    "action": "accept",
                    "display_name": p["display_name"],
                    "username": p["username"],
                    "onion": p["onion"],
                    "ed_pub": p["ed_pub"],
                    "x_pub": p["x_pub"],
                },
            )
        else:
            self.store.friends.pop(onion, None)
            self.store.messages.pop(onion, None)
            self.store.save()

        self._emit("friends_updated", self.store.friends)
        return web.json_response({"ok": True})

    async def handle_remove_friend(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        onion = str(body.get("onion", "")).strip()
        self.store.friends.pop(onion, None)
        self.store.messages.pop(onion, None)
        self.store.data["outbox"] = [x for x in self.store.outbox if x.get("to_onion") != onion]
        self.store.save()
        self._emit("friends_updated", self.store.friends)
        return web.json_response({"ok": True})

    async def handle_send_message(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        to_onion = str(body.get("to_onion", "")).strip()
        text = str(body.get("text", "")).strip()
        attachment = body.get("attachment")  # optional {name, mime, data_b64, size}

        friend = self.store.friends.get(to_onion)
        if not friend or friend.get("status") != "accepted":
            return web.json_response({"error": "You can only message accepted friends."}, status=400)
        if not text and not attachment:
            return web.json_response({"error": "Empty message."}, status=400)

        msg_id = str(uuid.uuid4())
        ts = time.time()
        msg = {
            "id": msg_id,
            "sender": "me",
            "text": text,
            "attachment": attachment,
            "timestamp": ts,
            "status": "queued",
        }
        self.store.append_message(to_onion, msg)
        self._emit("message", {"onion": to_onion, "message": msg})

        payload = {
            "type": "chat",
            "id": msg_id,
            "text": text,
            "attachment": attachment,
            "timestamp": ts,
        }
        delivered = await self._send_or_queue(to_onion, payload, msg_id=msg_id)
        if delivered:
            self.store.update_message_status(to_onion, msg_id, "delivered")
            self._emit("message_status", {"onion": to_onion, "id": msg_id, "status": "delivered"})

        return web.json_response({"message": msg})

    async def handle_send_media(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")

        reader = await request.multipart()
        to_onion = ""
        caption = ""
        media_id = str(uuid.uuid4())
        filename = "file.bin"
        mime = "application/octet-stream"
        file_path: Optional[Path] = None
        total_size = 0

        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "to_onion":
                to_onion = (await part.text()).strip()
            elif part.name == "caption":
                caption = (await part.text()).strip()
            elif part.name == "file":
                raw_name = Path(part.filename or "file.bin").name
                filename = re.sub(r"[^A-Za-z0-9._-]", "_", raw_name)[:120] or "file.bin"
                mime = part.headers.get("Content-Type", "application/octet-stream")
                file_path = self.store.media_dir / f"{media_id}_{filename}"
                with open(file_path, "wb") as f:
                    while True:
                        chunk = await part.read_chunk(1024 * 512)
                        if not chunk:
                            break
                        f.write(chunk)
                        total_size += len(chunk)

        friend = self.store.friends.get(to_onion)
        if not friend or friend.get("status") != "accepted" or file_path is None:
            if file_path and file_path.exists():
                file_path.unlink(missing_ok=True)
            return web.json_response({"error": "Invalid friend or missing file."}, status=400)

        ts = time.time()
        msg = {
            "id": media_id,
            "sender": "me",
            "text": caption,
            "attachment": {
                "media_id": media_id,
                "name": filename,
                "mime": mime,
                "size": total_size,
                "progress": 0,
            },
            "timestamp": ts,
            "status": "queued",
        }
        self.store.append_message(to_onion, msg)
        self._emit("message", {"onion": to_onion, "message": msg})

        asyncio.create_task(
            self._stream_media_to_peer(to_onion, media_id, file_path, filename, mime, total_size, caption, ts)
        )
        return web.json_response({"message": msg})

    @staticmethod
    def _file_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(1024 * 512)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()

    def _receive_chunk_and_assemble(
        self,
        media_id: str,
        idx: int,
        total_chunks: int,
        chunk_bytes: bytes,
        expected_sha256: str,
        final_path: Path,
    ) -> bool:
        """Store chunk idempotently by index and assemble + verify SHA-256 once all chunks arrive."""
        if idx < 0 or idx >= total_chunks or total_chunks <= 0:
            raise ValueError("Invalid chunk index")
        chunk_dir = self.store.media_dir / f".chunks_{media_id}"
        chunk_dir.mkdir(parents=True, exist_ok=True)
        chunk_file = chunk_dir / f"{idx:06d}.bin"
        if not chunk_file.is_file():
            chunk_file.write_bytes(chunk_bytes)

        received = list(chunk_dir.glob("*.bin"))
        if len(received) < total_chunks:
            return False

        tmp_out = self.store.media_dir / f".tmp_{media_id}"
        h = hashlib.sha256()
        with open(tmp_out, "wb") as out_f:
            for i in range(total_chunks):
                cf = chunk_dir / f"{i:06d}.bin"
                if not cf.is_file():
                    return False
                data = cf.read_bytes()
                h.update(data)
                out_f.write(data)

        shutil.rmtree(chunk_dir, ignore_errors=True)
        if expected_sha256 and h.hexdigest() != expected_sha256:
            tmp_out.unlink(missing_ok=True)
            raise ValueError("SHA-256 integrity check failed")
        tmp_out.replace(final_path)
        return True

    async def _stream_media_to_peer(
        self,
        to_onion: str,
        media_id: str,
        file_path: Path,
        filename: str,
        mime: str,
        total_size: int,
        caption: str,
        ts: float,
    ) -> None:
        chunk_size = 1024 * 1024  # 1 MB encrypted chunks for reliable Tor streaming
        total_chunks = max(1, (total_size + chunk_size - 1) // chunk_size)

        try:
            file_hash = self._file_sha256(file_path)
            with open(file_path, "rb") as f:
                for idx in range(total_chunks):
                    raw = f.read(chunk_size)
                    payload = {
                        "type": "media_chunk",
                        "media_id": media_id,
                        "name": filename,
                        "mime": mime,
                        "size": total_size,
                        "sha256": file_hash,
                        "caption": caption if idx == total_chunks - 1 else "",
                        "timestamp": ts,
                        "chunk_index": idx,
                        "total_chunks": total_chunks,
                        "data_b64": base64.b64encode(raw).decode("ascii"),
                    }
                    # Retry each chunk up to 5 times if Tor circuit hiccups
                    sent = False
                    for attempt in range(5):
                        if await self._send_p2p_direct(to_onion, payload):
                            sent = True
                            break
                        await asyncio.sleep(2 * (attempt + 1))

                    if not sent:
                        self.store.update_message_status(to_onion, media_id, "failed")
                        self._emit("message_status", {"onion": to_onion, "id": media_id, "status": "failed"})
                        return

                    pct = int(((idx + 1) * 100) / total_chunks)
                    self._emit(
                        "media_progress",
                        {"onion": to_onion, "id": media_id, "progress": pct},
                    )

            self.store.update_message_status(to_onion, media_id, "delivered")
            self._emit("message_status", {"onion": to_onion, "id": media_id, "status": "delivered"})
        except Exception:
            self.store.update_message_status(to_onion, media_id, "failed")
            self._emit("message_status", {"onion": to_onion, "id": media_id, "status": "failed"})

    async def handle_get_media(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        media_id = request.match_info.get("media_id", "")
        if not re.fullmatch(r"[A-Za-z0-9-]+", media_id):
            return web.Response(status=400, text="Invalid media id")
        for p in self.store.media_dir.glob(f"{media_id}_*"):
            if p.is_file():
                return web.FileResponse(p)
        return web.Response(status=404, text="Media not found")

    async def handle_mark_read(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        onion = str(body.get("onion", "")).strip()
        read_ids = self.store.mark_chat_read(onion)
        self._emit("friends_updated", self.store.friends)
        if read_ids and onion in self.store.friends:
            asyncio.create_task(
                self._send_p2p_direct(onion, {"type": "read", "ids": read_ids})
            )
        return web.json_response({"ok": True})

    async def handle_typing(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        onion = str(body.get("onion", "")).strip()
        is_typing = bool(body.get("typing", True))
        if onion in self.store.friends and self.store.friends[onion].get("status") == "accepted":
            asyncio.create_task(
                self._send_p2p_direct(onion, {"type": "typing", "typing": is_typing})
            )
        return web.json_response({"ok": True})

    async def handle_wipe(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        if self.tor:
            self.tor.stop()
            self.tor = None
        self.tor_ready = False
        self.tor_status = "Wiped"
        self.tor_progress = 0
        self.store.wipe_all()
        self._emit("state", self._public_state())
        return web.json_response({"ok": True})

    async def handle_set_avatar(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        p = self.store.profile
        if not p:
            return web.json_response({"error": "Not onboarded"}, status=400)
        body = await request.json()
        avatar_b64 = body.get("avatar_b64")
        if avatar_b64 and len(str(avatar_b64)) > 600_000:
            return web.json_response({"error": "Avatar image too large"}, status=400)
        p["avatar_b64"] = avatar_b64
        self.store.save()
        self._emit("state", self._public_state())

        # Share updated profile photo ONLY with accepted friends
        update_payload = {
            "type": "profile_update",
            "display_name": p["display_name"],
            "avatar_b64": avatar_b64,
        }
        for onion, friend in list(self.store.friends.items()):
            if friend.get("status") == "accepted":
                asyncio.create_task(self._send_or_queue(onion, update_payload))
        return web.json_response({"ok": True})

    async def handle_add_story(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        p = self.store.profile
        if not p:
            return web.json_response({"error": "Not onboarded"}, status=400)

        reader = await request.multipart()
        story_id = str(uuid.uuid4())
        text = ""
        bg_color = "#005c4b"
        caption = ""
        filename = ""
        mime = ""
        file_path: Optional[Path] = None
        total_size = 0

        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "text":
                text = (await part.text()).strip()[:500]
            elif part.name == "bg_color":
                bg_color = (await part.text()).strip()[:24] or "#005c4b"
            elif part.name == "caption":
                caption = (await part.text()).strip()[:200]
            elif part.name == "file":
                raw_name = Path(part.filename or "story.bin").name
                filename = re.sub(r"[^A-Za-z0-9._-]", "_", raw_name)[:120] or "story.bin"
                mime = part.headers.get("Content-Type", "application/octet-stream")
                file_path = self.store.media_dir / f"{story_id}_{filename}"
                with open(file_path, "wb") as f:
                    while True:
                        chunk = await part.read_chunk(1024 * 512)
                        if not chunk:
                            break
                        f.write(chunk)
                        total_size += len(chunk)

        if not text and file_path is None:
            return web.json_response({"error": "Story cannot be empty."}, status=400)

        now = time.time()
        story = {
            "id": story_id,
            "author_onion": p["onion"],
            "author_name": p["display_name"],
            "author_username": p["username"],
            "text": text,
            "bg_color": bg_color,
            "caption": caption,
            "media_id": story_id if file_path else None,
            "filename": filename if file_path else None,
            "mime": mime if file_path else None,
            "created_at": now,
            "expires_at": now + 24 * 3600,
            "viewed": True,
        }
        self.store.add_story(story)
        self._emit("stories_updated", self.store.stories)

        # Broadcast story ONLY to accepted friends (saved usernames)
        accepted = [o for o, f in self.store.friends.items() if f.get("status") == "accepted"]
        if file_path is None:
            payload = {
                "type": "story",
                "story": {k: v for k, v in story.items() if k != "viewed"},
            }
            for onion in accepted:
                asyncio.create_task(self._send_or_queue(onion, payload))
        else:
            for onion in accepted:
                asyncio.create_task(
                    self._stream_story_to_peer(onion, story, file_path, total_size)
                )

        return web.json_response({"story": story})

    async def _stream_story_to_peer(
        self, to_onion: str, story: Dict[str, Any], file_path: Path, total_size: int
    ) -> None:
        chunk_size = 1024 * 1024
        total_chunks = max(1, (total_size + chunk_size - 1) // chunk_size)
        try:
            file_hash = self._file_sha256(file_path)
            with open(file_path, "rb") as f:
                for idx in range(total_chunks):
                    raw = f.read(chunk_size)
                    payload = {
                        "type": "story_chunk",
                        "story": {k: v for k, v in story.items() if k != "viewed"},
                        "sha256": file_hash,
                        "chunk_index": idx,
                        "total_chunks": total_chunks,
                        "data_b64": base64.b64encode(raw).decode("ascii"),
                    }
                    sent = False
                    for attempt in range(5):
                        if await self._send_p2p_direct(to_onion, payload):
                            sent = True
                            break
                        await asyncio.sleep(2 * (attempt + 1))
                    if not sent:
                        return
        except Exception:
            return

    async def handle_view_story(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        story_id = str(body.get("id", "")).strip()
        self.store.mark_story_viewed(story_id)
        self._emit("stories_updated", self.store.stories)
        return web.json_response({"ok": True})

    async def handle_delete_chat(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        onion = str(body.get("onion", "")).strip()
        mode = str(body.get("mode", "me"))
        if mode == "everyone":
            self.store.shred_chat_permanently(onion)
            if onion in self.store.friends:
                await self._send_or_queue(onion, {"type": "shred_chat"})
        else:
            self.store.soft_delete_chat(onion)
        self._emit("state", self._public_state())
        return web.json_response({"ok": True})

    async def handle_restore_trash(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        trash_id = str(body.get("id", "")).strip()
        ok = self.store.restore_trash_item(trash_id)
        self._emit("state", self._public_state())
        return web.json_response({"ok": ok})

    async def handle_empty_trash(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        trash_id = body.get("id")
        self.store.empty_trash(trash_id=trash_id)
        self._emit("state", self._public_state())
        return web.json_response({"ok": True})

    async def handle_export_backup(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        body = await request.json()
        password = str(body.get("password", "")).strip()
        if len(password) < 4:
            return web.json_response({"error": "Use a backup password (at least 4 characters)."}, status=400)
        blob = self.store.export_encrypted_backup(password)
        uname = (self.store.profile or {}).get("username", "hush")
        headers = {"Content-Disposition": f'attachment; filename="{uname}_backup.hushbackup"'}
        return web.Response(body=blob, content_type="application/octet-stream", headers=headers)

    async def handle_import_backup(self, request: web.Request) -> web.Response:
        if not self._check_local_auth(request):
            return web.Response(status=403, text="Forbidden")
        reader = await request.multipart()
        password = ""
        blob = b""
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "password":
                password = (await part.text()).strip()
            elif part.name == "file":
                blob = await part.read(decode=False)
        if not blob or not password:
            return web.json_response({"error": "Backup file and password are required."}, status=400)
        if not self.store.import_encrypted_backup(blob, password):
            return web.json_response({"error": "Wrong backup password or invalid backup file."}, status=400)
        if not self.tor_ready and self.store.profile:
            await self._start_tor_service(self.store.tor_dir)
        self._emit("state", self._public_state())
        return web.json_response(self._public_state())

    # ------------------------------------------------------------------
    # P2P Tor Transport & Incoming Packet Handler
    # ------------------------------------------------------------------

    async def handle_p2p_packet(self, request: web.Request) -> web.Response:
        p = self.store.profile
        if not p:
            return web.Response(status=503, text="Node not initialized")
        try:
            packet = await request.json()
            sender_onion, sender_ed_pub, payload = decrypt_p2p_packet(p["x_priv"], packet)
        except Exception:
            return web.Response(status=400, text="Invalid packet")

        ptype = payload.get("type")
        friend = self.store.friends.get(sender_onion)

        # Verify sender's Ed25519 key matches stored friend key (if known)
        if friend and friend.get("ed_pub") != sender_ed_pub:
            return web.Response(status=403, text="Key mismatch")

        if ptype == "handshake":
            # Enforce strict identity binding: payload keys & onion MUST match verified outer envelope
            if not re.fullmatch(r"[a-z2-7]{56}\.onion", sender_onion):
                return web.Response(status=400, text="Invalid v3 onion address")
            if payload.get("onion") != sender_onion or payload.get("ed_pub") != sender_ed_pub:
                return web.Response(status=403, text="Identity binding mismatch")

            action = payload.get("action")
            if action == "request":
                if friend and friend.get("status") == "accepted":
                    return web.json_response({"ok": True})
                x_pub = str(payload.get("x_pub", "")).strip()
                if not x_pub:
                    return web.Response(status=400, text="Missing encryption key")
                if friend and friend.get("status") == "pending_out":
                    self.store.upsert_friend(sender_onion, {"status": "accepted", "online": True, "last_seen": time.time()})
                else:
                    self.store.upsert_friend(
                        sender_onion,
                        {
                            "display_name": str(payload.get("display_name", "Anonymous"))[:48],
                            "username": str(payload.get("username", "anon"))[:32],
                            "onion": sender_onion,
                            "ed_pub": sender_ed_pub,
                            "x_pub": x_pub,
                            "fingerprint": compute_fingerprint(sender_ed_pub, x_pub),
                            "status": "pending_in",
                            "online": True,
                            "last_seen": time.time(),
                            "unread": 0,
                        },
                    )
                self._emit("friends_updated", self.store.friends)
            elif action == "accept":
                if friend:
                    self.store.upsert_friend(
                        sender_onion,
                        {"status": "accepted", "online": True, "last_seen": time.time()},
                    )
                    self._emit("friends_updated", self.store.friends)
            return web.json_response({"ok": True})

        # If we already sent a friend request (pending_out) and they send us a valid signed packet,
        # that proves they accepted — auto-promote to accepted so no message is ever dropped!
        if friend and friend.get("status") == "pending_out":
            self.store.upsert_friend(
                sender_onion,
                {"status": "accepted", "online": True, "last_seen": time.time()},
            )
            friend = self.store.friends.get(sender_onion)
            self._emit("friends_updated", self.store.friends)

        # All other packet types require accepted friendship
        if not friend or friend.get("status") != "accepted":
            return web.Response(status=403, text="Not friends")

        # Mark friend online on any valid packet
        friend["online"] = True
        friend["last_seen"] = time.time()

        if ptype == "chat":
            msg = {
                "id": payload["id"],
                "sender": "them",
                "text": payload.get("text", ""),
                "attachment": payload.get("attachment"),
                "timestamp": payload.get("timestamp", time.time()),
                "status": "delivered",
            }
            self.store.append_message(sender_onion, msg)
            friend["unread"] = int(friend.get("unread", 0)) + 1
            self.store.save()
            self._emit("message", {"onion": sender_onion, "message": msg})
            self._emit("friends_updated", self.store.friends)
            return web.json_response({"ok": True, "ack": msg["id"]})

        if ptype == "media_chunk":
            media_id = str(payload.get("media_id", ""))
            if not re.fullmatch(r"[A-Za-z0-9-]+", media_id):
                return web.Response(status=400, text="Invalid media id")
            idx = int(payload.get("chunk_index", 0))
            total_chunks = int(payload.get("total_chunks", 1))
            raw_name = Path(str(payload.get("name", "file.bin"))).name
            filename = re.sub(r"[^A-Za-z0-9._-]", "_", raw_name)[:120] or "file.bin"
            final_path = self.store.media_dir / f"{media_id}_{filename}"
            chunk_bytes = base64.b64decode(payload.get("data_b64", ""))
            try:
                done = self._receive_chunk_and_assemble(
                    media_id, idx, total_chunks, chunk_bytes, str(payload.get("sha256", "")), final_path
                )
            except ValueError as exc:
                return web.Response(status=400, text=str(exc))

            if done:
                msg = {
                    "id": media_id,
                    "sender": "them",
                    "text": payload.get("caption", ""),
                    "attachment": {
                        "media_id": media_id,
                        "name": filename,
                        "mime": payload.get("mime", "application/octet-stream"),
                        "size": int(payload.get("size", final_path.stat().st_size)),
                    },
                    "timestamp": payload.get("timestamp", time.time()),
                    "status": "delivered",
                }
                self.store.append_message(sender_onion, msg)
                friend["unread"] = int(friend.get("unread", 0)) + 1
                self.store.save()
                self._emit("message", {"onion": sender_onion, "message": msg})
                self._emit("friends_updated", self.store.friends)
            return web.json_response({"ok": True, "chunk": idx})

        if ptype == "read":
            for mid in payload.get("ids", []):
                if self.store.update_message_status(sender_onion, mid, "read"):
                    self._emit("message_status", {"onion": sender_onion, "id": mid, "status": "read"})
            return web.json_response({"ok": True})

        if ptype == "typing":
            self._emit("typing", {"onion": sender_onion, "typing": bool(payload.get("typing", False))})
            return web.json_response({"ok": True})

        if ptype == "ping":
            self._emit("friends_updated", self.store.friends)
            return web.json_response({"ok": True, "pong": True})

        if ptype == "shred_chat":
            self.store.shred_chat_permanently(sender_onion)
            self._emit("state", self._public_state())
            return web.json_response({"ok": True, "shredded": True})

        if ptype == "profile_update":
            if payload.get("display_name"):
                friend["display_name"] = str(payload["display_name"])[:48]
            friend["avatar_b64"] = payload.get("avatar_b64")
            self.store.save()
            self._emit("friends_updated", self.store.friends)
            return web.json_response({"ok": True})

        if ptype == "story":
            st = payload.get("story") or {}
            st["author_onion"] = sender_onion
            st["viewed"] = False
            self.store.add_story(st)
            self._emit("stories_updated", self.store.stories)
            return web.json_response({"ok": True})

        if ptype == "story_chunk":
            st = payload.get("story") or {}
            media_id = str(st.get("media_id", ""))
            if not re.fullmatch(r"[A-Za-z0-9-]+", media_id):
                return web.Response(status=400, text="Invalid story id")
            idx = int(payload.get("chunk_index", 0))
            total_chunks = int(payload.get("total_chunks", 1))
            raw_name = Path(str(st.get("filename", "story.bin"))).name
            filename = re.sub(r"[^A-Za-z0-9._-]", "_", raw_name)[:120] or "story.bin"
            final_path = self.store.media_dir / f"{media_id}_{filename}"
            chunk_bytes = base64.b64decode(payload.get("data_b64", ""))
            try:
                done = self._receive_chunk_and_assemble(
                    media_id, idx, total_chunks, chunk_bytes, str(payload.get("sha256", "")), final_path
                )
            except ValueError as exc:
                return web.Response(status=400, text=str(exc))

            if done:
                st["author_onion"] = sender_onion
                st["viewed"] = False
                self.store.add_story(st)
                self._emit("stories_updated", self.store.stories)
            return web.json_response({"ok": True, "chunk": idx})

        return web.json_response({"ok": True})

    async def _send_p2p_direct(self, target_onion: str, payload: Dict[str, Any]) -> bool:
        p = self.store.profile
        friend = self.store.friends.get(target_onion)
        if not p or not friend or not self.tor or not self.tor_ready or not self.tor.socks_port:
            return False

        try:
            packet = encrypt_p2p_packet(
                sender_onion=p["onion"],
                sender_ed_priv_b64=p["ed_priv"],
                sender_ed_pub_b64=p["ed_pub"],
                recipient_x_pub_b64=friend["x_pub"],
                inner_payload=payload,
            )
            connector = ProxyConnector.from_url(
                f"socks5://127.0.0.1:{self.tor.socks_port}",
                rdns=True,
            )
            timeout = aiohttp.ClientTimeout(total=45, connect=30)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.post(f"http://{target_onion}/p2p/packet", json=packet) as resp:
                    ok = resp.status == 200
                    if ok:
                        friend["online"] = True
                        friend["last_seen"] = time.time()
                    return ok
        except Exception:
            return False

    async def _send_or_queue(
        self, target_onion: str, payload: Dict[str, Any], msg_id: Optional[str] = None
    ) -> bool:
        ok = await self._send_p2p_direct(target_onion, payload)
        if not ok:
            self.store.queue_outbox(
                {
                    "id": msg_id or str(uuid.uuid4()),
                    "to_onion": target_onion,
                    "payload": payload,
                }
            )
        return ok

    async def _outbox_worker(self) -> None:
        while True:
            try:
                await asyncio.sleep(6)
                if not self.tor_ready or not self.store.outbox:
                    continue
                for item in list(self.store.outbox):
                    to_onion = item["to_onion"]
                    if to_onion not in self.store.friends:
                        self.store.remove_outbox(item["id"])
                        continue
                    ok = await self._send_p2p_direct(to_onion, item["payload"])
                    if ok:
                        self.store.remove_outbox(item["id"])
                        if item["payload"].get("type") == "chat":
                            mid = item["payload"]["id"]
                            self.store.update_message_status(to_onion, mid, "delivered")
                            self._emit(
                                "message_status",
                                {"onion": to_onion, "id": mid, "status": "delivered"},
                            )
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(5)

    async def _presence_worker(self) -> None:
        while True:
            try:
                await asyncio.sleep(25)
                if not self.tor_ready:
                    continue
                changed = False
                for onion, friend in list(self.store.friends.items()):
                    if friend.get("status") == "pending_out":
                        # Check if peer is online / auto-heal missed accept
                        await self._send_p2p_direct(onion, {"type": "ping"})
                        continue
                    if friend.get("status") != "accepted":
                        continue
                    ok = await self._send_p2p_direct(onion, {"type": "ping"})
                    if friend.get("online") != ok:
                        friend["online"] = ok
                        changed = True
                if changed:
                    self._emit("friends_updated", self.store.friends)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(10)
