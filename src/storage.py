"""Local encrypted storage (Vault Mode) and RAM-only storage (Ghost Mode) for OnionChat."""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import io
import os
import shutil
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .crypto import decrypt_vault, encrypt_vault
from .tor_manager import get_app_data_dir


def _dpapi_protect(raw: bytes) -> bytes:
    """Encrypt bytes with Windows DPAPI (CurrentUser) so vault.key is never plaintext on disk."""
    if os.name != "nt":
        return raw
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(raw, len(raw))
    in_blob = DATA_BLOB(len(raw), buf)
    out_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), "HushVaultKey", None, None, None, 0, ctypes.byref(out_blob)):
        return raw
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(enc: bytes) -> bytes:
    if os.name != "nt":
        return enc
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(enc, len(enc))
    in_blob = DATA_BLOB(len(enc), buf)
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        return enc
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


class VaultStore:
    """Manages user identity, friends, messages, and outbound queue."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = base_dir or (get_app_data_dir() / "profile")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.vault_path = self.base_dir / "vault.enc"
        self.key_path = self.base_dir / "vault.key"
        self.tor_dir = self.base_dir / "tor_service"
        self.media_dir = self.base_dir / "media"
        self.media_dir.mkdir(parents=True, exist_ok=True)
        self._ghost_tmp: Optional[tempfile.TemporaryDirectory[str]] = None

        self.ghost_mode: bool = False
        self.passphrase: Optional[str] = None
        self.unlocked: bool = False
        self.data: Dict[str, Any] = self._empty_state()

    @staticmethod
    def _empty_state() -> Dict[str, Any]:
        return {
            "profile": None,
            "friends": {},
            "messages": {},
            "stories": [],
            "trash": [],
            "outbox": [],
        }

    def has_existing_vault(self) -> bool:
        return self.vault_path.is_file()

    def needs_passphrase(self) -> bool:
        return self.has_existing_vault() and not self.key_path.is_file()

    def init_ghost_mode(self) -> Path:
        self.ghost_mode = True
        self.unlocked = True
        self.data = self._empty_state()
        self._ghost_tmp = tempfile.TemporaryDirectory(prefix="hush_ghost_")
        tmp_path = Path(self._ghost_tmp.name)
        self.media_dir = tmp_path / "media"
        self.media_dir.mkdir(parents=True, exist_ok=True)
        return tmp_path / "tor_service"

    def init_vault_mode(self, passphrase: Optional[str] = None) -> Path:
        self.ghost_mode = False
        if passphrase:
            self.passphrase = passphrase
            if self.key_path.is_file():
                self.key_path.unlink()
        else:
            # Convenience mode: random local key protected with Windows DPAPI (CurrentUser)
            if self.key_path.is_file():
                raw = self.key_path.read_text(encoding="utf-8").strip()
                if raw.startswith("dpapi:"):
                    self.passphrase = _dpapi_unprotect(base64.b64decode(raw[6:])).decode("utf-8")
                else:
                    self.passphrase = raw
            else:
                self.passphrase = os.urandom(32).hex()
                protected = "dpapi:" + base64.b64encode(_dpapi_protect(self.passphrase.encode("utf-8"))).decode("ascii")
                self.key_path.write_text(protected, encoding="utf-8")
        self.unlocked = True
        return self.tor_dir

    def unlock_existing(self, passphrase: Optional[str] = None) -> bool:
        if not self.has_existing_vault():
            return False
        if not passphrase and self.key_path.is_file():
            raw = self.key_path.read_text(encoding="utf-8").strip()
            if raw.startswith("dpapi:"):
                passphrase = _dpapi_unprotect(base64.b64decode(raw[6:])).decode("utf-8")
            else:
                passphrase = raw
        if not passphrase:
            return False
        try:
            blob = self.vault_path.read_bytes()
            self.data = decrypt_vault(blob, passphrase)
            self.passphrase = passphrase
            self.ghost_mode = False
            self.unlocked = True
            return True
        except Exception:
            return False

    def save(self) -> None:
        if self.ghost_mode or not self.unlocked or not self.passphrase:
            return
        blob = encrypt_vault(self.data, self.passphrase)
        tmp = self.vault_path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(self.vault_path)

    def set_profile(self, profile: Dict[str, Any]) -> None:
        self.data["profile"] = profile
        self.save()

    @property
    def profile(self) -> Optional[Dict[str, Any]]:
        return self.data.get("profile")

    @property
    def friends(self) -> Dict[str, Dict[str, Any]]:
        return self.data.setdefault("friends", {})

    @property
    def messages(self) -> Dict[str, List[Dict[str, Any]]]:
        return self.data.setdefault("messages", {})

    @property
    def outbox(self) -> List[Dict[str, Any]]:
        return self.data.setdefault("outbox", [])

    @property
    def stories(self) -> List[Dict[str, Any]]:
        return self.data.setdefault("stories", [])

    @property
    def trash(self) -> List[Dict[str, Any]]:
        return self.data.setdefault("trash", [])

    def _shred_media_id(self, media_id: Optional[str]) -> None:
        if not media_id:
            return
        for p in self.media_dir.glob(f"{media_id}_*"):
            if p.is_file():
                try:
                    p.write_bytes(os.urandom(min(1024 * 1024, max(64, p.stat().st_size))))
                    p.unlink()
                except Exception:
                    pass

    def soft_delete_chat(self, onion: str) -> Optional[Dict[str, Any]]:
        msgs = self.messages.get(onion, [])
        if not msgs:
            return None
        friend_name = self.friends.get(onion, {}).get("display_name", onion[:12])
        entry = {
            "id": str(uuid.uuid4()),
            "kind": "chat",
            "onion": onion,
            "friend_name": friend_name,
            "messages": list(msgs),
            "deleted_at": time.time(),
        }
        self.trash.append(entry)
        self.messages[onion] = []
        self.save()
        return entry

    def shred_chat_permanently(self, onion: str) -> None:
        """Overwrite and destroy all messages and media for a peer (used on remote shred)."""
        msgs = self.messages.get(onion, [])
        for m in msgs:
            att = m.get("attachment") or {}
            self._shred_media_id(att.get("media_id"))
            m["text"] = os.urandom(24).hex()
        self.messages[onion] = []
        # Also remove any trashed items for this peer
        remaining_trash = []
        for t in self.trash:
            if t.get("onion") == onion:
                for m in t.get("messages", []):
                    self._shred_media_id((m.get("attachment") or {}).get("media_id"))
            else:
                remaining_trash.append(t)
        self.data["trash"] = remaining_trash
        self.save()

    def restore_trash_item(self, trash_id: str) -> bool:
        for i, item in enumerate(self.trash):
            if item.get("id") == trash_id:
                onion = item["onion"]
                existing = self.messages.setdefault(onion, [])
                existing_ids = {m.get("id") for m in existing}
                for m in item.get("messages", []):
                    if m.get("id") not in existing_ids:
                        existing.append(m)
                existing.sort(key=lambda x: float(x.get("timestamp", 0)))
                self.trash.pop(i)
                self.save()
                return True
        return False

    def empty_trash(self, trash_id: Optional[str] = None) -> None:
        if trash_id:
            kept = []
            for item in self.trash:
                if item.get("id") == trash_id:
                    for m in item.get("messages", []):
                        self._shred_media_id((m.get("attachment") or {}).get("media_id"))
                else:
                    kept.append(item)
            self.data["trash"] = kept
        else:
            for item in self.trash:
                for m in item.get("messages", []):
                    self._shred_media_id((m.get("attachment") or {}).get("media_id"))
            self.data["trash"] = []
        self.save()

    def export_encrypted_backup(self, password: str) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if self.tor_dir.exists():
                for p in self.tor_dir.rglob("*"):
                    if p.is_file():
                        zf.write(p, arcname=f"tor_service/{p.relative_to(self.tor_dir).as_posix()}")
            if self.media_dir.exists():
                for p in self.media_dir.rglob("*"):
                    if p.is_file() and not p.name.startswith("."):
                        zf.write(p, arcname=f"media/{p.relative_to(self.media_dir).as_posix()}")
        archive_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        return encrypt_vault({"v": 1, "data": self.data, "archive_b64": archive_b64}, password)

    def import_encrypted_backup(self, blob: bytes, password: str) -> bool:
        try:
            payload = decrypt_vault(blob, password)
            data = payload["data"]
            archive_bytes = base64.b64decode(payload["archive_b64"])
        except Exception:
            return False

        self.init_vault_mode(passphrase=self.passphrase)
        self.data = data
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                rel = Path(member.filename)
                if ".." in rel.parts:
                    continue
                if rel.parts[0] == "tor_service":
                    out = self.tor_dir.joinpath(*rel.parts[1:])
                elif rel.parts[0] == "media":
                    out = self.media_dir.joinpath(*rel.parts[1:])
                else:
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        self.save()
        return True

    def add_story(self, story: Dict[str, Any]) -> None:
        self.prune_expired_stories()
        if not any(s.get("id") == story.get("id") for s in self.stories):
            self.stories.append(story)
            self.save()

    def mark_story_viewed(self, story_id: str) -> None:
        for s in self.stories:
            if s.get("id") == story_id and not s.get("viewed"):
                s["viewed"] = True
                self.save()
                break

    def prune_expired_stories(self) -> None:
        now = time.time()
        before = len(self.stories)
        self.data["stories"] = [s for s in self.stories if float(s.get("expires_at", 0)) > now]
        if len(self.data["stories"]) != before:
            self.save()

    def upsert_friend(self, onion: str, info: Dict[str, Any]) -> None:
        existing = self.friends.get(onion, {})
        existing.update(info)
        self.friends[onion] = existing
        self.messages.setdefault(onion, [])
        self.save()

    def append_message(self, onion: str, msg: Dict[str, Any]) -> None:
        lst = self.messages.setdefault(onion, [])
        # Deduplicate by message id
        if any(m.get("id") == msg.get("id") for m in lst):
            return
        lst.append(msg)
        self.save()

    def update_message_status(self, onion: str, msg_id: str, status: str) -> bool:
        rank = {"queued": 0, "sent": 1, "delivered": 2, "read": 3}
        for m in self.messages.get(onion, []):
            if m.get("id") == msg_id:
                cur = m.get("status", "queued")
                if rank.get(status, 0) > rank.get(cur, 0):
                    m["status"] = status
                    self.save()
                    return True
        return False

    def mark_chat_read(self, onion: str) -> List[str]:
        friend = self.friends.get(onion)
        if friend:
            friend["unread"] = 0
        read_ids: List[str] = []
        for m in self.messages.get(onion, []):
            if m.get("sender") == "them" and m.get("status") != "read":
                m["status"] = "read"
                read_ids.append(m["id"])
        if friend or read_ids:
            self.save()
        return read_ids

    def queue_outbox(self, item: Dict[str, Any]) -> None:
        item.setdefault("created_at", time.time())
        self.outbox.append(item)
        self.save()

    def remove_outbox(self, item_id: str) -> None:
        self.data["outbox"] = [x for x in self.outbox if x.get("id") != item_id]
        self.save()

    def cleanup_ghost(self) -> None:
        if self._ghost_tmp is not None:
            try:
                self._ghost_tmp.cleanup()
            except Exception:
                pass
            self._ghost_tmp = None

    def wipe_all(self) -> None:
        self.data = self._empty_state()
        self.unlocked = False
        self.passphrase = None
        self.cleanup_ghost()
        for p in (self.vault_path, self.key_path):
            if p.is_file():
                try:
                    p.write_bytes(os.urandom(max(64, p.stat().st_size)))
                    p.unlink()
                except Exception:
                    pass
        if self.tor_dir.exists():
            shutil.rmtree(self.tor_dir, ignore_errors=True)
        if self.media_dir.exists():
            shutil.rmtree(self.media_dir, ignore_errors=True)
            self.media_dir.mkdir(parents=True, exist_ok=True)
