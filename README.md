# Hush — Serverless Private P2P Messenger

A WhatsApp-style desktop chat application with **zero central servers**, **zero phone numbers**, and **zero third-party data possession**. Every installation runs its own embedded **Tor v3 Onion Service** directly from `Hush.exe`.

## Features
- **100% Serverless & Private**: Messages and media travel directly peer-to-peer over Tor v3 hidden services (`socks5` with remote DNS resolution).
- **End-to-End Encrypted (E2EE)**: Every packet is encrypted with **X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305** and signed with **Ed25519** identity keys.
- **No Phone Number / No Sign-Up**: On first launch, enter your **Name** and choose a **@username**; Hush generates your cryptographic identity and QR card locally.
- **Drag & Drop QR Friend Adding**: Share your QR Card PNG (or `hush://v1` invite link). Friends can drag & drop your QR image anywhere onto the Hush window to decode it offline and connect.
- **4K Video & Large File Sharing**: Chunked, SHA-256 verified, E2EE P2P streaming up to 1 GB.
- **Profile Photos & 24-Hour Stories**: Encrypted and shared **only with your saved friends**.
- **Encrypted Local Vault or Ghost Mode**:
  - **Encrypted Vault**: Local `vault.enc` encrypted with PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305 (with Windows DPAPI protection when no passphrase is set, or passphrase-derived key when set).
  - **Ghost Mode**: RAM-only session with zero disk traces when closed.

## Using the Standalone Executable
Run `dist/Hush.exe` directly — no Python, Git, or manual Tor installation required.

## Running from Source
```powershell
cd onion_chat
.\venv\Scripts\python.exe main.py
```

### Testing Two Accounts Locally
```powershell
.\venv\Scripts\python.exe main.py --profile .\tmp_alice
.\venv\Scripts\python.exe main.py --profile .\tmp_bob
```

## Rebuilding `Hush.exe`
```powershell
.\venv\Scripts\python.exe setup_tor.py   # Downloads official Tor Expert Bundle into ./tor/
.\venv\Scripts\python.exe build_exe.py   # Packages everything into dist/Hush.exe
```
