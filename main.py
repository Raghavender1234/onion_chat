"""Entry point for Hush desktop application with System Tray & Windows notifications."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Optional

import pystray
import webview
from PIL import Image, ImageDraw
from winotify import Notification, audio

from src.p2p_node import OnionChatNode


def get_ui_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")) / "ui"
    return Path(__file__).resolve().parent / "ui"


def _create_tray_image() -> Image.Image:
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((4, 4, size - 4, size - 4), fill="#00a884")
    # Inner chat bubble / lock accent
    draw.rounded_rectangle((18, 20, 46, 42), radius=8, fill="#0b141a")
    draw.polygon([(24, 41), (20, 50), (31, 41)], fill="#0b141a")
    return img


def main() -> None:
    parser = argparse.ArgumentParser(description="Hush — Private Serverless Messenger")
    parser.add_argument("--profile", type=str, default=None, help="Custom profile directory (for testing multiple instances)")
    parser.add_argument("--browser", action="store_true", help="Open in default browser instead of native WebView window")
    args = parser.parse_args()

    profile_dir = Path(args.profile).resolve() if args.profile else None
    ui_dir = get_ui_dir()

    window_ref: dict[str, Optional[webview.Window]] = {"win": None}
    ui_state = {"visible": True, "minimized": False, "quitting": False}

    def show_window() -> None:
        win = window_ref["win"]
        if win is not None:
            try:
                win.show()
                win.restore()
            except Exception:
                pass
            ui_state["visible"] = True
            ui_state["minimized"] = False

    def on_notify(title: str, body: str) -> None:
        # Show native Windows pop-up notification when window is hidden in tray or minimized
        if ui_state["visible"] and not ui_state["minimized"]:
            return
        if os.name != "nt":
            return
        try:
            toast = Notification(
                app_id="Hush Private Messenger",
                title=title,
                msg=body,
                duration="short",
            )
            toast.set_audio(audio.Default, loop=False)
            toast.show()
        except Exception:
            pass

    loop = asyncio.new_event_loop()
    node = OnionChatNode(ui_dir=ui_dir, profile_dir=profile_dir, on_notify=on_notify)
    ready_event = threading.Event()
    port_holder = {"port": 0}

    def run_server() -> None:
        asyncio.set_event_loop(loop)
        port_holder["port"] = loop.run_until_complete(node.start())
        ready_event.set()
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(node.stop())
            loop.close()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    ready_event.wait(timeout=10)

    url = f"http://127.0.0.1:{port_holder['port']}/"

    if args.browser:
        webbrowser.open(url)
        try:
            server_thread.join()
        except KeyboardInterrupt:
            pass
    else:
        window = webview.create_window(
            "Hush — Private Messenger",
            url,
            width=1120,
            height=740,
            min_size=(820, 560),
        )
        window_ref["win"] = window

        def on_closing() -> bool:
            if ui_state["quitting"]:
                return True
            ui_state["visible"] = False
            try:
                window.hide()
            except Exception:
                pass
            return False  # Hide to System Tray instead of killing Tor

        def on_minimized() -> None:
            ui_state["minimized"] = True

        def on_restored() -> None:
            ui_state["minimized"] = False
            ui_state["visible"] = True

        window.events.closing += on_closing
        window.events.minimized += on_minimized
        window.events.restored += on_restored

        tray_icon: Optional[pystray.Icon] = None

        def quit_app(icon: pystray.Icon, _item: pystray.MenuItem) -> None:
            ui_state["quitting"] = True
            icon.stop()
            try:
                window.destroy()
            except Exception:
                pass

        tray_icon = pystray.Icon(
            "Hush",
            _create_tray_image(),
            "Hush — Private Messenger (Running in Background)",
            menu=pystray.Menu(
                pystray.MenuItem("Open Hush", lambda _i, _it: show_window(), default=True),
                pystray.MenuItem("Quit Hush", quit_app),
            ),
        )
        tray_icon.run_detached()

        webview.start()
        if tray_icon is not None:
            try:
                tray_icon.stop()
            except Exception:
                pass

    loop.call_soon_threadsafe(loop.stop)
    server_thread.join(timeout=5)


if __name__ == "__main__":
    main()
