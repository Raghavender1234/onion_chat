"""Embedded Tor daemon manager for OnionChat.

Handles:
- Locating bundled tor.exe (PyInstaller _MEIPASS, local tor/, or AppData)
- Auto-downloading the official Tor Expert Bundle from torproject.org if missing
- Launching an isolated Tor instance with a v3 Hidden Service
- Reading bootstrap progress and the generated .onion hostname
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable, Optional


def get_app_data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / "Hush"
    d.mkdir(parents=True, exist_ok=True)
    return d


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def find_tor_binary() -> Optional[Path]:
    exe_name = "tor.exe" if os.name == "nt" else "tor"
    app_tor_dir = get_app_data_dir() / "tor"
    app_tor_exe = app_tor_dir / exe_name

    # If bundled inside PyInstaller _MEIPASS, copy once to stable %LOCALAPPDATA%\Hush\tor
    # so Windows Firewall does not see a new _MEIxxxxx temp path on every launch.
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass_tor = Path(getattr(sys, "_MEIPASS")) / "tor"
        if (meipass_tor / exe_name).is_file():
            if not app_tor_exe.is_file():
                shutil.copytree(meipass_tor, app_tor_dir, dirs_exist_ok=True)
            return app_tor_exe

    project_root = Path(__file__).resolve().parent.parent
    for c in (project_root / "tor" / exe_name, app_tor_exe):
        if c.is_file():
            return c

    which = shutil.which("tor")
    if which:
        return Path(which)
    return None


def download_tor_expert_bundle(
    dest_dir: Optional[Path] = None,
    status_cb: Optional[Callable[[str], None]] = None,
) -> Path:
    """Download and extract the official Windows x86_64 Tor Expert Bundle."""
    if os.name != "nt":
        raise RuntimeError("Auto-download is only configured for Windows; install 'tor' via your package manager.")

    target_dir = dest_dir or (get_app_data_dir() / "tor")
    target_dir.mkdir(parents=True, exist_ok=True)
    tor_exe = target_dir / "tor.exe"
    if tor_exe.is_file():
        return tor_exe

    def log(msg: str) -> None:
        if status_cb:
            status_cb(msg)

    log("Fetching latest Tor Expert Bundle link from torproject.org...")
    req = urllib.request.Request(
        "https://www.torproject.org/download/tor/",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        html = resp.read().decode("utf-8", errors="ignore")

    matches = re.findall(
        r"https://archive\.torproject\.org/tor-package-archive/torbrowser/[^\"'\s]+tor-expert-bundle-windows-x86_64-[^\"'\s]+\.tar\.gz",
        html,
    )
    if not matches:
        matches = re.findall(
            r"https://[^\"'\s]+tor-expert-bundle-windows-x86_64[^\"'\s]+\.tar\.gz",
            html,
        )
    if not matches:
        raise RuntimeError("Could not locate Tor Expert Bundle download URL on torproject.org.")

    url = matches[0]
    log(f"Downloading Tor Expert Bundle ({url.rsplit('/', 1)[-1]})...")

    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / "tor-bundle.tar.gz"
        dl_req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(dl_req, timeout=120) as resp, open(archive_path, "wb") as f:
            total = int(resp.headers.get("Content-Length") or 0)
            downloaded = 0
            while True:
                chunk = resp.read(1024 * 128)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = int(downloaded * 100 / total)
                    log(f"Downloading Tor Expert Bundle... {pct}%")

        log("Extracting Tor binaries...")
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                # Safely extract only tor/ files (no path traversal)
                parts = Path(member.name).parts
                if "tor" in parts:
                    idx = parts.index("tor")
                    rel = Path(*parts[idx + 1 :])
                    if rel.name and ".." not in rel.parts:
                        out_path = target_dir / rel
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        with tar.extractfile(member) as src, open(out_path, "wb") as dst:
                            if src is not None:
                                shutil.copyfileobj(src, dst)

    if not tor_exe.is_file():
        raise RuntimeError("Extraction finished but tor.exe was not found.")

    log("Tor Expert Bundle ready.")
    return tor_exe


class TorManager:
    """Manages an isolated Tor process + v3 Onion Service."""

    def __init__(self, tor_data_dir: Path, local_http_port: int) -> None:
        self.tor_data_dir = tor_data_dir
        self.local_http_port = local_http_port
        self.socks_port: int = 0
        self.control_port: int = 0
        self.onion_address: Optional[str] = None
        self.bootstrap_progress: int = 0
        self.status_message: str = "Initializing secure network..."
        self.process: Optional[subprocess.Popen[str]] = None
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._ready_event = asyncio.Event()
        self._tls_blocked_event = asyncio.Event()
        self._last_tor_pct: int = 0

    @property
    def hidden_service_dir(self) -> Path:
        return self.tor_data_dir / "hidden_service"

    async def start(self, status_cb: Optional[Callable[[str, int], None]] = None) -> str:
        def report(msg: str, pct: int) -> None:
            self.status_message = msg
            self.bootstrap_progress = pct
            if status_cb:
                status_cb(msg, pct)

        tor_bin = find_tor_binary()
        if tor_bin is None:
            report("Setting up encrypted transport (first-time setup)...", 5)
            loop = asyncio.get_running_loop()
            tor_bin = await loop.run_in_executor(
                None,
                lambda: download_tor_expert_bundle(status_cb=lambda m: report("Downloading security engine...", 10)),
            )

        self.tor_data_dir.mkdir(parents=True, exist_ok=True)
        data_dir = self.tor_data_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        hs_dir = self.hidden_service_dir
        hs_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(hs_dir, 0o700)

        pt_dir = tor_bin.parent / "pluggable_transports"
        lyrebird = pt_dir / ("lyrebird.exe" if os.name == "nt" else "lyrebird")
        pt_cfg = pt_dir / "pt_config.json"
        has_bridges = lyrebird.is_file() and pt_cfg.is_file()

        # Try direct Tor first (fast-fallback to obfs4 bridges if blocked/intercepted)
        connected = await self._launch_tor_attempt(
            tor_bin=tor_bin,
            data_dir=data_dir,
            hs_dir=hs_dir,
            use_bridges=False,
            lyrebird=lyrebird,
            pt_cfg=pt_cfg,
            report=report,
            timeout=25 if has_bridges else 120,
        )

        if not connected and has_bridges:
            self.stop()
            report("Direct route blocked; switching to encrypted bridge mode...", 15)
            connected = await self._launch_tor_attempt(
                tor_bin=tor_bin,
                data_dir=data_dir,
                hs_dir=hs_dir,
                use_bridges=True,
                lyrebird=lyrebird,
                pt_cfg=pt_cfg,
                report=report,
                timeout=120,
            )

        if not connected:
            self.stop()
            raise RuntimeError(
                "Secure network timed out while connecting. Check your internet connection or firewall."
            )

        hostname_file = hs_dir / "hostname"
        for _ in range(30):
            if hostname_file.is_file():
                onion = hostname_file.read_text(encoding="utf-8").strip()
                if onion.endswith(".onion"):
                    self.onion_address = onion
                    report("Encrypted Network Connected", 100)
                    return onion
            await asyncio.sleep(0.2)

        raise RuntimeError("Connected, but private identity address was not created.")

    async def _launch_tor_attempt(
        self,
        tor_bin: Path,
        data_dir: Path,
        hs_dir: Path,
        use_bridges: bool,
        lyrebird: Path,
        pt_cfg: Path,
        report: Callable[[str, int], None],
        timeout: int,
    ) -> bool:
        self._ready_event = asyncio.Event()
        self._tls_blocked_event = asyncio.Event()
        self._last_tor_pct = 0

        self.socks_port = find_free_port()
        self.control_port = find_free_port()

        torrc_path = self.tor_data_dir / "torrc"
        torrc_lines = [
            f"SocksPort 127.0.0.1:{self.socks_port}",
            f"ControlPort 127.0.0.1:{self.control_port}",
            f"DataDirectory {data_dir}",
            f"HiddenServiceDir {hs_dir}",
            "HiddenServiceVersion 3",
            f"HiddenServicePort 80 127.0.0.1:{self.local_http_port}",
            "Log notice stdout",
            f"Log notice file {self.tor_data_dir / 'tor.log'}",
            "AvoidDiskWrites 1",
        ]
        geoip = tor_bin.parent / "geoip"
        geoip6 = tor_bin.parent / "geoip6"
        if geoip.is_file():
            torrc_lines.append(f"GeoIPFile {geoip}")
        if geoip6.is_file():
            torrc_lines.append(f"GeoIPv6File {geoip6}")

        if use_bridges:
            cfg = json.loads(pt_cfg.read_text(encoding="utf-8"))
            obfs4_bridges = cfg.get("bridges", {}).get("obfs4", [])
            if obfs4_bridges:
                torrc_lines.append("UseBridges 1")
                torrc_lines.append(f"ClientTransportPlugin obfs4 exec {lyrebird}")
                for b in obfs4_bridges:
                    torrc_lines.append(f"Bridge {b}")

        torrc_path.write_text("\n".join(torrc_lines) + "\n", encoding="utf-8")

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

        report("Starting private connection...", 15)
        self.process = subprocess.Popen(
            [str(tor_bin), "-f", str(torrc_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )

        self._reader_task = asyncio.create_task(self._monitor_stdout(report))

        ready_task = asyncio.create_task(self._ready_event.wait())
        blocked_task = asyncio.create_task(self._tls_blocked_event.wait())
        try:
            done, pending = await asyncio.wait(
                {ready_task, blocked_task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
            if ready_task in done:
                return True
            return False
        except Exception:
            ready_task.cancel()
            blocked_task.cancel()
            return False

    async def _monitor_stdout(self, report: Callable[[str, int], None]) -> None:
        if not self.process or not self.process.stdout:
            return
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, self.process.stdout.readline)
            if not line:
                break
            if "bad CERTS cell" in line or "Problem bootstrapping" in line:
                if self._last_tor_pct < 25:
                    self._tls_blocked_event.set()
            m = re.search(r"Bootstrapped (\d+)%[^:]*:\s*(.+)", line)
            if m:
                pct = int(m.group(1))
                self._last_tor_pct = pct
                mapped_pct = max(15, min(99, pct))
                if pct < 50:
                    friendly = "Establishing encrypted relays..."
                elif pct < 85:
                    friendly = "Verifying private route..."
                else:
                    friendly = "Finalizing secure identity..."
                report(f"{friendly} ({pct}%)", mapped_pct)
                if pct >= 100:
                    self._ready_event.set()

    def stop(self) -> None:
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        if self.process and self.process.poll() is None:
            pid = self.process.pid
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
                        timeout=5,
                    )
                else:
                    self.process.terminate()
                    self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.process = None
