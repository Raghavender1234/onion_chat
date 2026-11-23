"""Build a standalone single-file OnionChat.exe with PyInstaller."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    ui_dir = root / "ui"
    tor_dir = root / "tor"

    sep = ";" if os.name == "nt" else ":"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "Hush",
        "--add-data",
        f"{ui_dir}{sep}ui",
    ]

    if (tor_dir / "tor.exe").is_file():
        print("Bundling local tor/ into OnionChat.exe (100% offline self-contained)...")
        cmd.extend(["--add-data", f"{tor_dir}{sep}tor"])
    else:
        print("Note: ./tor/tor.exe not found. OnionChat.exe will auto-download Tor on first run.")
        print("Tip: Run 'python setup_tor.py' first to bundle Tor directly inside the .exe.")

    cmd.append(str(root / "main.py"))
    subprocess.check_call(cmd, cwd=str(root))
    print(f"\nBuild complete! Executable: {root / 'dist' / 'Hush.exe'}")


if __name__ == "__main__":
    main()
