"""Download the official Tor Expert Bundle into ./tor/ for bundling into OnionChat.exe."""

from pathlib import Path
from src.tor_manager import download_tor_expert_bundle

if __name__ == "__main__":
    tor_dir = Path(__file__).resolve().parent / "tor"
    exe = download_tor_expert_bundle(dest_dir=tor_dir, status_cb=print)
    print(f"Tor ready at: {exe}")
