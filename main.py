"""Entry point for OnionChat desktop application."""

from __future__ import annotations

import argparse
import asyncio
import sys
import threading
import webbrowser
from pathlib import Path

import webview

from src.p2p_node import OnionChatNode


def get_ui_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")) / "ui"
    return Path(__file__).resolve().parent / "ui"


def main() -> None:
    parser = argparse.ArgumentParser(description="OnionChat — Anonymous Serverless Tor Messenger")
    parser.add_argument("--profile", type=str, default=None, help="Custom profile directory (for testing multiple instances)")
    parser.add_argument("--browser", action="store_true", help="Open in default browser instead of native WebView window")
    args = parser.parse_args()

    profile_dir = Path(args.profile).resolve() if args.profile else None
    ui_dir = get_ui_dir()

    loop = asyncio.new_event_loop()
    node = OnionChatNode(ui_dir=ui_dir, profile_dir=profile_dir)
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
        webview.start()

    loop.call_soon_threadsafe(loop.stop)
    server_thread.join(timeout=5)


if __name__ == "__main__":
    main()
