"""QR code generation and offline decoding utilities for OnionChat."""

from __future__ import annotations

import base64
import io
import json
import urllib.parse
from typing import Any, Dict, Optional

import cv2
import numpy as np
import qrcode
from PIL import Image, ImageDraw, ImageFont

from .crypto import compute_fingerprint

INVITE_SCHEME = "hush://v1"


def build_invite_uri(
    display_name: str,
    username: str,
    onion_address: str,
    ed_pub: str,
    x_pub: str,
) -> str:
    payload = {
        "v": 1,
        "n": display_name,
        "u": username,
        "o": onion_address,
        "ek": ed_pub,
        "xk": x_pub,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{INVITE_SCHEME}?d={encoded}"


def parse_invite_uri(text: str) -> Dict[str, Any]:
    """Parse a hush://v1?d=... URI or raw JSON invite string."""
    text = text.strip()
    if text.startswith("hush://") or text.startswith("onionchat://"):
        parsed = urllib.parse.urlparse(text)
        qs = urllib.parse.parse_qs(parsed.query)
        d = qs.get("d", [""])[0]
        if not d:
            raise ValueError("Missing invite payload in URI")
        pad = "=" * ((4 - len(d) % 4) % 4)
        data = json.loads(base64.urlsafe_b64decode(d + pad).decode("utf-8"))
    elif text.startswith("{"):
        data = json.loads(text)
    else:
        raise ValueError("Not a valid Hush invite link or QR payload")

    onion = str(data.get("o", "")).strip().lower()
    if not onion.endswith(".onion") or len(onion) < 20:
        raise ValueError("Invalid .onion address in invite")

    ed_pub = str(data.get("ek", "")).strip()
    x_pub = str(data.get("xk", "")).strip()
    if not ed_pub or not x_pub:
        raise ValueError("Missing public keys in invite")

    return {
        "display_name": str(data.get("n", "Anonymous"))[:48],
        "username": str(data.get("u", "anon"))[:32],
        "onion": onion,
        "ed_pub": ed_pub,
        "x_pub": x_pub,
        "fingerprint": compute_fingerprint(ed_pub, x_pub),
    }


def generate_qr_png(invite_uri: str, box_size: int = 8) -> bytes:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=4,
    )
    qr.add_data(invite_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0b141a", back_color="#ffffff").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_invite_card_png(
    display_name: str,
    username: str,
    onion_address: str,
    ed_pub: str,
    x_pub: str,
) -> bytes:
    """Render a shareable PNG card containing the QR code and .onion handle."""
    uri = build_invite_uri(display_name, username, onion_address, ed_pub, x_pub)
    qr_bytes = generate_qr_png(uri, box_size=7)
    qr_img = Image.open(io.BytesIO(qr_bytes)).convert("RGB")

    card_w = max(460, qr_img.width + 96)
    card_h = qr_img.height + 230
    card = Image.new("RGB", (card_w, card_h), "#0b141a")
    draw = ImageDraw.Draw(card)

    # Header accent bar
    draw.rectangle([(0, 0), (card_w, 10)], fill="#00a884")

    font_title = ImageFont.load_default()
    font_sub = ImageFont.load_default()

    # Center QR with rounded white frame
    pad = 14
    qr_x = (card_w - qr_img.width) // 2
    qr_y = 76
    draw.rounded_rectangle(
        [(qr_x - pad, qr_y - pad), (qr_x + qr_img.width + pad, qr_y + qr_img.height + pad)],
        radius=16,
        fill="#ffffff",
    )
    card.paste(qr_img, (qr_x, qr_y))

    # Text
    title_text = f"Hush  |  {display_name} (@{username})"
    draw.text((28, 28), title_text, fill="#e9edef", font=font_title)
    draw.text((28, 46), "Drag & drop this QR image into Hush to connect privately", fill="#8696a0", font=font_sub)

    footer_y = qr_y + qr_img.height + 30
    short_id = f"{onion_address[:10]}...{onion_address.replace('.onion', '')[-8:]}"
    draw.text((28, footer_y), f"Private ID: {short_id}", fill="#00a884", font=font_sub)
    fp = compute_fingerprint(ed_pub, x_pub)
    draw.text((28, footer_y + 22), f"Safety Key: {fp}", fill="#8696a0", font=font_sub)
    draw.text((28, footer_y + 44), "Zero Servers  •  End-to-End Encrypted  •  Direct P2P", fill="#667781", font=font_sub)

    buf = io.BytesIO()
    card.save(buf, format="PNG")
    return buf.getvalue()


def decode_qr_from_bytes(image_bytes: bytes) -> Optional[str]:
    """Decode a QR code from raw image bytes using OpenCV with robust preprocessing."""
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        # Fallback via Pillow (e.g. WebP/GIF/BMP edge cases)
        try:
            pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
        except Exception:
            return None

    detector = cv2.QRCodeDetector()

    def _try_detect(mat: np.ndarray) -> Optional[str]:
        try:
            val, _, _ = detector.detectAndDecode(mat)
            if val:
                return val.strip()
            ok, vals, _, _ = detector.detectAndDecodeMulti(mat)
            if ok and vals:
                for v in vals:
                    if v:
                        return v.strip()
        except Exception:
            pass
        return None

    # 1. Direct color image
    res = _try_detect(img)
    if res:
        return res

    # 2. Grayscale + Otsu threshold
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    res = _try_detect(gray)
    if res:
        return res

    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    res = _try_detect(thresh)
    if res:
        return res

    # 3. Multi-scale retries (handles dense QR codes or small screenshots)
    h, w = gray.shape[:2]
    for scale in (0.5, 0.75, 1.5, 2.0):
        resized = cv2.resize(
            thresh,
            (max(64, int(w * scale)), max(64, int(h * scale))),
            interpolation=cv2.INTER_AREA if scale < 1 else cv2.INTER_NEAREST,
        )
        res = _try_detect(resized)
        if res:
            return res

    # 4. Inverted (white-on-dark QR)
    inv = cv2.bitwise_not(gray)
    res = _try_detect(inv)
    if res:
        return res

    return None
