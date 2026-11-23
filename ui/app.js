(() => {
  const TOKEN = window.__ONIONCHAT_TOKEN__ || "";

  let state = {
    has_vault: false,
    needs_passphrase: false,
    unlocked: false,
    ghost_mode: false,
    profile: null,
    friends: {},
    messages: {},
    stories: [],
    trash: [],
    tor: { ready: false, status: "Initializing...", progress: 0, error: null },
  };

  let activeOnion = null;
  let pendingAttachment = null;
  let pendingInviteUri = null;
  let activeStory = null;
  let selectedStoryColor = "#005c4b";
  let typingTimer = null;
  let peerTypingTimer = null;

  const $ = (id) => document.getElementById(id);

  async function api(path, options = {}) {
    const headers = options.headers || {};
    headers["X-Local-Token"] = TOKEN;
    if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(path, { ...options, headers });
    const contentType = resp.headers.get("content-type") || "";
    const data = contentType.includes("application/json") ? await resp.json() : await resp.text();
    if (!resp.ok) {
      throw new Error(data.error || data || `Request failed (${resp.status})`);
    }
    return data;
  }

  function toast(msg, isError = false) {
    const el = document.createElement("div");
    el.className = `toast ${isError ? "error" : ""}`;
    el.textContent = msg;
    $("toast-container").appendChild(el);
    setTimeout(() => el.remove(), 3800);
  }

  function initials(name) {
    return (name || "?").trim().slice(0, 2).toUpperCase();
  }

  function formatTime(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ------------------------------------------------------------------
  // SSE Real-time Events
  // ------------------------------------------------------------------
  function connectSSE() {
    const es = new EventSource(`/api/events?token=${encodeURIComponent(TOKEN)}`);
    es.addEventListener("state", (e) => {
      state = JSON.parse(e.data);
      renderAll();
    });
    es.addEventListener("tor_status", (e) => {
      const t = JSON.parse(e.data);
      state.tor = { ...state.tor, ...t };
      renderTorStatus();
    });
    es.addEventListener("friends_updated", (e) => {
      state.friends = JSON.parse(e.data);
      renderSidebar();
      renderStories();
      if (activeOnion) renderActiveChatHeader();
    });
    es.addEventListener("stories_updated", (e) => {
      state.stories = JSON.parse(e.data);
      renderStories();
    });
    es.addEventListener("message", (e) => {
      const { onion, message } = JSON.parse(e.data);
      state.messages[onion] = state.messages[onion] || [];
      if (!state.messages[onion].some((m) => m.id === message.id)) {
        state.messages[onion].push(message);
      }
      if (activeOnion === onion) {
        renderMessages();
        if (message.sender === "them") {
          api("/api/messages/read", { method: "POST", body: JSON.stringify({ onion }) }).catch(() => {});
        }
      }
      renderSidebar();
    });
    es.addEventListener("message_status", (e) => {
      const { onion, id, status } = JSON.parse(e.data);
      const list = state.messages[onion] || [];
      const msg = list.find((m) => m.id === id);
      if (msg) {
        msg.status = status;
        if (activeOnion === onion) renderMessages();
      }
    });
    es.addEventListener("media_progress", (e) => {
      const { onion, id, progress } = JSON.parse(e.data);
      const list = state.messages[onion] || [];
      const msg = list.find((m) => m.id === id);
      if (msg && msg.attachment) {
        msg.attachment.progress = progress;
        if (activeOnion === onion) renderMessages();
      }
    });
    es.addEventListener("typing", (e) => {
      const { onion, typing } = JSON.parse(e.data);
      if (activeOnion === onion) {
        $("typing-indicator").classList.toggle("hidden", !typing);
        clearTimeout(peerTypingTimer);
        if (typing) {
          peerTypingTimer = setTimeout(() => $("typing-indicator").classList.add("hidden"), 4000);
        }
      }
    });
  }

  // ------------------------------------------------------------------
  // Rendering
  // ------------------------------------------------------------------
  function renderAll() {
    if (!state.unlocked || !state.profile) {
      $("auth-screen").classList.remove("hidden");
      $("app-shell").classList.add("hidden");
      $("tor-boot-panel").classList.add("hidden");
      if (state.has_vault && state.needs_passphrase) {
        $("unlock-panel").classList.remove("hidden");
        $("onboard-panel").classList.add("hidden");
      } else if (state.has_vault && !state.needs_passphrase && !state.unlocked) {
        // Auto-unlock convenience vault
        unlockVault(null);
      } else {
        $("unlock-panel").classList.add("hidden");
        $("onboard-panel").classList.remove("hidden");
      }
      return;
    }

    $("auth-screen").classList.add("hidden");
    $("app-shell").classList.remove("hidden");

    const p = state.profile;
    renderAvatar($("my-avatar"), p.display_name, p.avatar_b64);
    $("my-display-name").textContent = p.display_name + (state.ghost_mode ? " (Ghost)" : "");
    $("my-username").textContent = `@${p.username}`;

    renderTorStatus();
    renderStories();
    renderSidebar();
    renderActiveChat();
  }

  function renderAvatar(el, name, avatarB64, badgeHtml = "") {
    if (avatarB64) {
      el.innerHTML = `<img src="${avatarB64}" alt="${escapeHtml(name)}" />${badgeHtml}`;
    } else {
      el.innerHTML = `${escapeHtml(initials(name))}${badgeHtml}`;
    }
  }

  function renderStories() {
    const listEl = $("stories-list");
    if (!listEl) return;
    listEl.innerHTML = "";
    const now = Date.now() / 1000;
    const valid = (state.stories || []).filter((s) => (s.expires_at || 0) > now);

    // Group by author_onion (latest story per author)
    const byAuthor = new Map();
    for (const s of valid) {
      byAuthor.set(s.author_onion, s);
    }

    for (const s of byAuthor.values()) {
      const isMe = state.profile && s.author_onion === state.profile.onion;
      const friend = state.friends[s.author_onion];
      const avatarB64 = isMe ? state.profile.avatar_b64 : friend?.avatar_b64;
      const bubble = document.createElement("div");
      bubble.className = "story-bubble";
      bubble.innerHTML = `
        <div class="story-ring ${s.viewed ? "viewed" : ""}">
          ${avatarB64 ? `<img src="${avatarB64}" alt="${escapeHtml(s.author_name)}" />` : escapeHtml(initials(s.author_name))}
        </div>
        <span>${isMe ? "You" : escapeHtml(s.author_name)}</span>
      `;
      bubble.onclick = () => openStoryViewer(s);
      listEl.appendChild(bubble);
    }
  }

  function openStoryViewer(story) {
    activeStory = story;
    const isMe = state.profile && story.author_onion === state.profile.onion;
    const friend = state.friends[story.author_onion];
    const avatarB64 = isMe ? state.profile.avatar_b64 : friend?.avatar_b64;
    renderAvatar($("story-viewer-avatar"), story.author_name, avatarB64);
    $("story-viewer-name").textContent = `${story.author_name} (@${story.author_username})`;
    $("story-viewer-time").textContent = formatTime(story.created_at);

    const body = $("story-viewer-body");
    body.innerHTML = "";
    if (story.media_id) {
      const url = `/api/media/${encodeURIComponent(story.media_id)}?token=${encodeURIComponent(TOKEN)}`;
      if ((story.mime || "").startsWith("video/")) {
        body.innerHTML = `<video controls autoplay src="${url}"></video>`;
      } else {
        body.innerHTML = `<img src="${url}" alt="Story" />`;
      }
    } else {
      body.innerHTML = `<div class="story-text-card" style="background:${escapeHtml(story.bg_color || "#005c4b")}">${escapeHtml(story.text)}</div>`;
    }

    const cap = $("story-viewer-caption");
    if (story.caption) {
      cap.textContent = story.caption;
      cap.classList.remove("hidden");
    } else {
      cap.classList.add("hidden");
    }

    $("story-viewer-reply").classList.toggle("hidden", isMe);
    $("modal-story-viewer").classList.remove("hidden");
    if (!story.viewed) {
      api("/api/stories/view", { method: "POST", body: JSON.stringify({ id: story.id }) }).catch(() => {});
    }
  }

  function renderTorStatus() {
    const t = state.tor || {};
    $("tor-boot-msg").textContent = t.status || "Connecting...";
    $("tor-boot-fill").style.width = `${t.progress || 5}%`;

    const dot = $("tor-dot");
    const txt = $("tor-strip-text");
    if (t.ready && state.profile) {
      dot.classList.add("online");
      txt.textContent = `Encrypted Network Ready • @${state.profile.username}`;
    } else {
      dot.classList.remove("online");
      txt.textContent = t.status || "Connecting securely...";
    }
  }

  function renderSidebar() {
    const q = ($("search-friends").value || "").trim().toLowerCase();
    const friends = Object.values(state.friends || {});

    // Friend Requests (pending_in)
    const incoming = friends.filter((f) => f.status === "pending_in");
    const reqSec = $("requests-section");
    const reqList = $("requests-list");
    reqList.innerHTML = "";
    if (incoming.length > 0) {
      reqSec.classList.remove("hidden");
      for (const f of incoming) {
        const row = document.createElement("div");
        row.className = "request-item";
        row.innerHTML = `
          <div>
            <strong>${escapeHtml(f.display_name)}</strong>
            <div class="muted">@${escapeHtml(f.username)}</div>
          </div>
          <div class="request-actions">
            <button class="btn btn-primary btn-sm" data-accept="${escapeHtml(f.onion)}">Accept</button>
            <button class="btn btn-danger-ghost btn-sm" data-decline="${escapeHtml(f.onion)}">✕</button>
          </div>
        `;
        reqList.appendChild(row);
      }
      reqList.querySelectorAll("[data-accept]").forEach((btn) => {
        btn.onclick = () => respondFriend(btn.dataset.accept, true);
      });
      reqList.querySelectorAll("[data-decline]").forEach((btn) => {
        btn.onclick = () => respondFriend(btn.dataset.decline, false);
      });
    } else {
      reqSec.classList.add("hidden");
    }

    // Accepted + pending_out friends
    const chatPeers = friends
      .filter((f) => f.status !== "pending_in")
      .filter(
        (f) =>
          !q ||
          f.display_name.toLowerCase().includes(q) ||
          f.username.toLowerCase().includes(q) ||
          f.onion.toLowerCase().includes(q)
      );

    // Sort by latest message timestamp
    chatPeers.sort((a, b) => {
      const ma = (state.messages[a.onion] || []).slice(-1)[0];
      const mb = (state.messages[b.onion] || []).slice(-1)[0];
      return (mb?.timestamp || 0) - (ma?.timestamp || 0);
    });

    const listEl = $("friends-list");
    listEl.innerHTML = "";
    if (chatPeers.length === 0) {
      listEl.innerHTML = `
        <div class="empty-friends">
          <p>No friends yet.</p>
          <p class="muted">Share your <strong>QR Code</strong> or drag &amp; drop a friend's QR image anywhere here!</p>
        </div>
      `;
      return;
    }

    for (const f of chatPeers) {
      const msgs = state.messages[f.onion] || [];
      const last = msgs[msgs.length - 1];
      let preview = f.status === "pending_out" ? "⏳ Waiting for acceptance..." : "Tap to chat anonymously";
      if (last) {
        const prefix = last.sender === "me" ? "You: " : "";
        preview = prefix + (last.text || (last.attachment ? `📎 ${last.attachment.name}` : ""));
      }

      const item = document.createElement("div");
      item.className = `friend-item ${activeOnion === f.onion ? "active" : ""}`;
      const avatarContent = f.avatar_b64
        ? `<img src="${f.avatar_b64}" alt="${escapeHtml(f.display_name)}" />`
        : escapeHtml(initials(f.display_name));
      item.innerHTML = `
        <div class="avatar">
          ${avatarContent}
          <span class="online-badge ${f.online ? "online" : ""}"></span>
        </div>
        <div class="friend-meta">
          <div class="friend-top">
            <span class="friend-name">${escapeHtml(f.display_name)} <span class="muted">@${escapeHtml(f.username)}</span></span>
            <span class="friend-time">${last ? formatTime(last.timestamp) : ""}</span>
          </div>
          <div class="friend-bottom">
            <span class="friend-preview-text">${escapeHtml(preview)}</span>
            ${f.unread > 0 ? `<span class="unread-pill">${f.unread}</span>` : ""}
          </div>
        </div>
      `;
      item.onclick = () => selectChat(f.onion);
      listEl.appendChild(item);
    }
  }

  function selectChat(onion) {
    activeOnion = onion;
    renderSidebar();
    renderActiveChat();
    api("/api/messages/read", { method: "POST", body: JSON.stringify({ onion }) }).catch(() => {});
  }

  function renderActiveChatHeader() {
    const f = state.friends[activeOnion];
    if (!f) return;
    renderAvatar($("peer-avatar"), f.display_name, f.avatar_b64);
    $("peer-name").textContent = f.display_name;
    $("peer-username").textContent = `@${f.username}`;
    if (f.status === "pending_out") {
      $("peer-status").textContent = "Friend request sent • Waiting for acceptance";
    } else if (f.online) {
      $("peer-status").textContent = "🟢 Online • End-to-End Encrypted";
    } else {
      $("peer-status").textContent = "⚪ Offline (messages queue until online)";
    }
  }

  function renderActiveChat() {
    if (!activeOnion || !state.friends[activeOnion]) {
      $("chat-empty-state").classList.remove("hidden");
      $("active-chat").classList.add("hidden");
      return;
    }
    $("chat-empty-state").classList.add("hidden");
    $("active-chat").classList.remove("hidden");
    renderActiveChatHeader();
    renderMessages();
  }

  function renderMessages() {
    const listEl = $("messages-list");
    const msgs = state.messages[activeOnion] || [];
    listEl.innerHTML = "";

    for (const m of msgs) {
      const row = document.createElement("div");
      row.className = `msg-row ${m.sender === "me" ? "me" : "them"}`;

      let attHtml = "";
      if (m.attachment) {
        const mime = m.attachment.mime || "application/octet-stream";
        const srcUrl = m.attachment.media_id
          ? `/api/media/${encodeURIComponent(m.attachment.media_id)}?token=${encodeURIComponent(TOKEN)}`
          : m.attachment.data_b64
          ? `data:${mime};base64,${m.attachment.data_b64}`
          : "";
        if (srcUrl) {
          if (mime.startsWith("image/")) {
            attHtml = `<div class="msg-attachment"><img src="${srcUrl}" alt="${escapeHtml(m.attachment.name)}" /></div>`;
          } else if (mime.startsWith("video/")) {
            attHtml = `<div class="msg-attachment"><video controls preload="metadata" style="max-width:300px;max-height:240px;border-radius:8px;display:block;" src="${srcUrl}"></video></div>`;
          } else if (mime.startsWith("audio/")) {
            attHtml = `<div class="msg-attachment"><audio controls src="${srcUrl}" style="max-width:260px;"></audio></div>`;
          } else {
            const sizeMb = m.attachment.size ? ` (${(m.attachment.size / (1024 * 1024)).toFixed(1)} MB)` : "";
            attHtml = `<div class="msg-attachment"><a class="file-chip" href="${srcUrl}" download="${escapeHtml(m.attachment.name)}">📄 ${escapeHtml(m.attachment.name)}${sizeMb}</a></div>`;
          }
        }
        if (m.sender === "me" && typeof m.attachment.progress === "number" && m.attachment.progress < 100 && m.status === "queued") {
          attHtml += `<div class="muted" style="font-size:0.72rem;margin-bottom:4px;">Sending encrypted media... ${m.attachment.progress}%</div>`;
        }
      }

      let tickHtml = "";
      if (m.sender === "me") {
        if (m.status === "failed") tickHtml = `<span class="tick" style="color:var(--danger)" title="Transfer failed">⚠️ Failed</span>`;
        else if (m.status === "queued") tickHtml = `<span class="tick" title="Queued for delivery">🕒</span>`;
        else if (m.status === "sent") tickHtml = `<span class="tick">✓</span>`;
        else if (m.status === "delivered") tickHtml = `<span class="tick">✓✓</span>`;
        else if (m.status === "read") tickHtml = `<span class="tick read">✓✓</span>`;
      }

      row.innerHTML = `
        <div class="msg-bubble">
          ${attHtml}
          ${m.text ? `<div>${escapeHtml(m.text).replace(/\n/g, "<br/>")}</div>` : ""}
          <div class="msg-meta">
            <span>${formatTime(m.timestamp)}</span>
            ${tickHtml}
          </div>
        </div>
      `;
      listEl.appendChild(row);
    }

    const vp = $("messages-viewport");
    vp.scrollTop = vp.scrollHeight;
  }

  // ------------------------------------------------------------------
  // Actions
  // ------------------------------------------------------------------
  async function unlockVault(passphrase) {
    $("unlock-panel").classList.add("hidden");
    $("onboard-panel").classList.add("hidden");
    $("tor-boot-panel").classList.remove("hidden");
    try {
      state = await api("/api/unlock", {
        method: "POST",
        body: JSON.stringify({ passphrase }),
      });
      renderAll();
    } catch (err) {
      toast(err.message, true);
      $("tor-boot-panel").classList.add("hidden");
      $("unlock-panel").classList.remove("hidden");
    }
  }

  async function createIdentity() {
    const display_name = $("input-display-name").value.trim();
    const username = $("input-username").value.trim().toLowerCase();
    const ghost_mode = document.querySelector('input[name="storage-mode"]:checked').value === "ghost";
    const passphrase = $("input-passphrase").value;

    if (!display_name || !username) {
      toast("Please enter your name and username.", true);
      return;
    }

    $("onboard-panel").classList.add("hidden");
    $("tor-boot-panel").classList.remove("hidden");

    try {
      state = await api("/api/onboard", {
        method: "POST",
        body: JSON.stringify({ display_name, username, ghost_mode, passphrase }),
      });
      toast("Your private Hush profile is ready!");
      renderAll();
    } catch (err) {
      toast(err.message, true);
      $("tor-boot-panel").classList.add("hidden");
      $("onboard-panel").classList.remove("hidden");
    }
  }

  async function respondFriend(onion, accept) {
    try {
      await api("/api/friends/respond", {
        method: "POST",
        body: JSON.stringify({ onion, accept }),
      });
      toast(accept ? "Friend added! You can chat now." : "Request declined.");
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function sendMessage() {
    if (!activeOnion) return;
    const input = $("message-input");
    const text = input.value.trim();
    if (!text && !pendingAttachment) return;

    input.value = "";
    input.style.height = "auto";
    const fileToSend = pendingAttachment;
    clearAttachment();

    try {
      if (fileToSend) {
        const fd = new FormData();
        fd.append("to_onion", activeOnion);
        fd.append("caption", text);
        fd.append("file", fileToSend);
        await api("/api/media/send", { method: "POST", body: fd });
      } else {
        await api("/api/messages/send", {
          method: "POST",
          body: JSON.stringify({ to_onion: activeOnion, text }),
        });
      }
    } catch (err) {
      toast(err.message, true);
    }
  }

  function clearAttachment() {
    pendingAttachment = null;
    $("attachment-bar").classList.add("hidden");
    $("file-attach-input").value = "";
  }

  // ------------------------------------------------------------------
  // QR Code Modals & Drag-and-Drop
  // ------------------------------------------------------------------
  function openMyQrModal() {
    if (!state.profile) return;
    const p = state.profile;
    $("my-qr-img").src = `/api/qr?token=${encodeURIComponent(TOKEN)}&t=${Date.now()}`;
    $("qr-card-name").textContent = p.display_name;
    $("qr-card-user").textContent = `@${p.username}`;
    $("qr-onion-box").textContent = p.invite_uri;
    $("qr-safety-key").textContent = p.fingerprint;
    $("modal-my-qr").classList.remove("hidden");
  }

  function openAddFriendModal() {
    $("friend-preview").classList.add("hidden");
    $("input-invite-uri").value = "";
    pendingInviteUri = null;
    $("modal-add-friend").classList.remove("hidden");
  }

  function showFriendPreview(invite, rawUri) {
    pendingInviteUri = rawUri;
    $("preview-avatar").textContent = initials(invite.display_name);
    $("preview-name").textContent = invite.display_name;
    $("preview-user").textContent = `@${invite.username}`;
    $("preview-onion").textContent = `Private ID: ${invite.onion.slice(0, 10)}...`;
    $("preview-fp").textContent = invite.fingerprint;
    $("friend-preview").classList.remove("hidden");
  }

  async function decodeQrFile(file) {
    const fd = new FormData();
    fd.append("file", file);
    try {
      const res = await api("/api/friends/decode-qr", { method: "POST", body: fd });
      openAddFriendModal();
      $("input-invite-uri").value = res.raw;
      showFriendPreview(res.invite, res.raw);
      toast(`Decoded QR for ${res.invite.display_name} (@${res.invite.username})`);
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function previewInviteText(raw) {
    if (!raw.startsWith("hush://") && !raw.startsWith("onionchat://") && !raw.startsWith("{")) {
      toast("Paste a valid hush:// invite link.", true);
      return;
    }
    try {
      const res = await api("/api/friends/add", {
        method: "POST",
        body: JSON.stringify({ invite_uri: raw }),
      });
      $("modal-add-friend").classList.add("hidden");
      toast(`Friend request sent to ${res.friend.display_name}!`);
      selectChat(res.friend.onion);
    } catch (err) {
      toast(err.message, true);
    }
  }

  // ------------------------------------------------------------------
  // Event Bindings
  // ------------------------------------------------------------------
  function bindEvents() {
    // Storage mode cards
    document.querySelectorAll('input[name="storage-mode"]').forEach((radio) => {
      radio.onchange = () => {
        const isGhost = radio.value === "ghost" && radio.checked;
        $("mode-vault-card").classList.toggle("selected", !isGhost);
        $("mode-ghost-card").classList.toggle("selected", isGhost);
        $("passphrase-field").classList.toggle("hidden", isGhost);
      };
    });

    $("btn-create-identity").onclick = createIdentity;
    $("btn-unlock").onclick = () => unlockVault($("unlock-passphrase").value);
    $("unlock-passphrase").onkeydown = (e) => {
      if (e.key === "Enter") unlockVault($("unlock-passphrase").value);
    };

    const doWipe = async () => {
      if (!confirm("Permanently delete your local profile, keys, friends, media, and all messages?")) return;
      await api("/api/wipe", { method: "POST" });
      activeOnion = null;
      toast("All local data wiped.");
    };
    $("btn-panic-wipe").onclick = doWipe;
    $("btn-wipe-locked").onclick = doWipe;

    $("btn-theme").onclick = () => {
      const cur = document.documentElement.getAttribute("data-theme");
      document.documentElement.setAttribute("data-theme", cur === "dark" ? "light" : "dark");
    };

    $("btn-my-qr").onclick = openMyQrModal;
    $("btn-empty-my-qr").onclick = openMyQrModal;

    // Trash & Encrypted Backup Modal
    const renderTrashList = () => {
      const box = $("trash-list");
      box.innerHTML = "";
      const items = state.trash || [];
      if (items.length === 0) {
        box.innerHTML = `<p class="muted small">Trash is empty.</p>`;
        return;
      }
      for (const t of items) {
        const row = document.createElement("div");
        row.className = "request-item";
        row.innerHTML = `
          <div>
            <strong>${escapeHtml(t.friend_name)}</strong>
            <div class="muted small">${(t.messages || []).length} messages • ${formatTime(t.deleted_at)}</div>
          </div>
          <div class="request-actions">
            <button class="btn btn-primary btn-sm" data-restore="${escapeHtml(t.id)}">Restore</button>
            <button class="btn btn-danger-ghost btn-sm" data-shred="${escapeHtml(t.id)}">Shred</button>
          </div>
        `;
        box.appendChild(row);
      }
      box.querySelectorAll("[data-restore]").forEach((b) => {
        b.onclick = async () => {
          await api("/api/trash/restore", { method: "POST", body: JSON.stringify({ id: b.dataset.restore }) });
          toast("Chat restored!");
          renderTrashList();
        };
      });
      box.querySelectorAll("[data-shred]").forEach((b) => {
        b.onclick = async () => {
          await api("/api/trash/empty", { method: "POST", body: JSON.stringify({ id: b.dataset.shred }) });
          toast("Permanently shredded.");
          renderTrashList();
        };
      });
    };

    $("btn-trash-backup").onclick = () => {
      renderTrashList();
      $("modal-trash-backup").classList.remove("hidden");
    };
    $("btn-empty-all-trash").onclick = async () => {
      await api("/api/trash/empty", { method: "POST", body: JSON.stringify({}) });
      toast("All trash permanently shredded.");
      renderTrashList();
    };
    $("btn-export-backup").onclick = async () => {
      const password = $("backup-password").value.trim();
      if (password.length < 4) {
        toast("Enter a backup password (at least 4 characters).", true);
        return;
      }
      try {
        const resp = await fetch("/api/backup/export", {
          method: "POST",
          headers: { "X-Local-Token": TOKEN, "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          throw new Error(err.error || "Export failed");
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${state.profile?.username || "hush"}_backup.hushbackup`;
        a.click();
        URL.revokeObjectURL(url);
        toast("Encrypted backup downloaded!");
      } catch (err) {
        toast(err.message, true);
      }
    };
    $("btn-import-backup").onclick = () => $("backup-file-input").click();
    $("backup-file-input").onchange = async (e) => {
      const file = e.target.files[0];
      const password = $("backup-password").value.trim();
      if (!file || !password) {
        toast("Enter your backup password first, then select the .hushbackup file.", true);
        return;
      }
      const fd = new FormData();
      fd.append("password", password);
      fd.append("file", file);
      try {
        state = await api("/api/backup/import", { method: "POST", body: fd });
        $("modal-trash-backup").classList.add("hidden");
        renderAll();
        toast("Encrypted backup restored!");
      } catch (err) {
        toast(err.message, true);
      }
    };

    // Delete / Shred Chat Modal
    $("btn-delete-chat").onclick = () => {
      if (activeOnion) $("modal-delete-chat").classList.remove("hidden");
    };
    $("btn-delete-for-me").onclick = async () => {
      if (!activeOnion) return;
      await api("/api/chat/delete", { method: "POST", body: JSON.stringify({ onion: activeOnion, mode: "me" }) });
      $("modal-delete-chat").classList.add("hidden");
      toast("Chat moved to your Trash (recoverable).");
    };
    $("btn-shred-for-both").onclick = async () => {
      if (!activeOnion) return;
      if (!confirm("Permanently shred this chat for BOTH you and your friend? Nobody will be able to recover it.")) return;
      await api("/api/chat/delete", { method: "POST", body: JSON.stringify({ onion: activeOnion, mode: "everyone" }) });
      $("modal-delete-chat").classList.add("hidden");
      toast("Chat shredded for both sides!");
    };

    // Profile Photo upload (resized to 180x180 & shared with saved friends only)
    $("btn-change-avatar").onclick = () => $("avatar-file-input").click();
    $("avatar-file-input").onchange = (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const img = new Image();
      img.onload = async () => {
        const size = 180;
        const canvas = document.createElement("canvas");
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext("2d");
        const minSide = Math.min(img.width, img.height);
        const sx = (img.width - minSide) / 2;
        const sy = (img.height - minSide) / 2;
        ctx.drawImage(img, sx, sy, minSide, minSide, 0, 0, size, size);
        const avatar_b64 = canvas.toDataURL("image/jpeg", 0.82);
        try {
          await api("/api/profile/avatar", { method: "POST", body: JSON.stringify({ avatar_b64 }) });
          toast("Profile photo updated & synced to saved friends!");
        } catch (err) {
          toast(err.message, true);
        }
      };
      img.src = URL.createObjectURL(file);
    };

    // Stories (24h, Saved Friends Only)
    $("btn-add-story").onclick = () => {
      $("story-text-input").value = "";
      $("story-caption-input").value = "";
      $("story-file-input").value = "";
      $("modal-add-story").classList.remove("hidden");
    };
    document.querySelectorAll("#story-colors .swatch").forEach((sw) => {
      sw.onclick = () => {
        document.querySelectorAll("#story-colors .swatch").forEach((s) => s.classList.remove("active"));
        sw.classList.add("active");
        selectedStoryColor = sw.dataset.color;
      };
    });
    $("btn-publish-story").onclick = async () => {
      const text = $("story-text-input").value.trim();
      const caption = $("story-caption-input").value.trim();
      const file = $("story-file-input").files[0];
      if (!text && !file) {
        toast("Write a status or choose a photo/video.", true);
        return;
      }
      const fd = new FormData();
      fd.append("text", text);
      fd.append("bg_color", selectedStoryColor);
      fd.append("caption", caption);
      if (file) fd.append("file", file);
      try {
        await api("/api/stories/add", { method: "POST", body: fd });
        $("modal-add-story").classList.add("hidden");
        toast("Story shared with your saved friends!");
      } catch (err) {
        toast(err.message, true);
      }
    };
    $("btn-send-story-reply").onclick = async () => {
      if (!activeStory) return;
      const reply = $("story-reply-input").value.trim();
      if (!reply) return;
      $("story-reply-input").value = "";
      try {
        await api("/api/messages/send", {
          method: "POST",
          body: JSON.stringify({ to_onion: activeStory.author_onion, text: `Replied to story: ${reply}` }),
        });
        $("modal-story-viewer").classList.add("hidden");
        selectChat(activeStory.author_onion);
      } catch (err) {
        toast(err.message, true);
      }
    };

    $("btn-add-friend").onclick = openAddFriendModal;
    $("btn-empty-add-friend").onclick = openAddFriendModal;

    document.querySelectorAll(".modal-close").forEach((btn) => {
      btn.onclick = () => $(btn.dataset.close).classList.add("hidden");
    });

    $("tor-strip").onclick = () => {
      if (state.profile?.invite_uri) {
        navigator.clipboard.writeText(state.profile.invite_uri);
        toast("Copied your Hush invite link!");
      }
    };
    $("qr-onion-box").onclick = () => {
      if (state.profile?.invite_uri) {
        navigator.clipboard.writeText(state.profile.invite_uri);
        toast("Copied Hush invite link!");
      }
    };
    $("btn-copy-invite").onclick = () => {
      if (state.profile?.invite_uri) {
        navigator.clipboard.writeText(state.profile.invite_uri);
        toast("Copied Hush invite link!");
      }
    };
    $("btn-download-qr-card").onclick = () => {
      window.location.href = `/api/qr/card?token=${encodeURIComponent(TOKEN)}`;
    };

    // Browse QR image
    $("btn-browse-qr").onclick = () => $("qr-file-input").click();
    $("qr-file-input").onchange = (e) => {
      if (e.target.files[0]) decodeQrFile(e.target.files[0]);
    };

    $("btn-parse-invite").onclick = () => {
      const raw = $("input-invite-uri").value.trim();
      if (raw) previewInviteText(raw);
    };

    $("btn-confirm-add-friend").onclick = async () => {
      if (!pendingInviteUri) return;
      try {
        const res = await api("/api/friends/add", {
          method: "POST",
          body: JSON.stringify({ invite_uri: pendingInviteUri }),
        });
        $("modal-add-friend").classList.add("hidden");
        toast(`Friend request sent to ${res.friend.display_name}!`);
        selectChat(res.friend.onion);
      } catch (err) {
        toast(err.message, true);
      }
    };

    // Global Drag & Drop for QR Codes
    let dragCounter = 0;
    window.addEventListener("dragenter", (e) => {
      if (!state.unlocked) return;
      e.preventDefault();
      dragCounter++;
      $("drop-overlay").classList.remove("hidden");
    });
    window.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dragCounter = Math.max(0, dragCounter - 1);
      if (dragCounter === 0) $("drop-overlay").classList.add("hidden");
    });
    window.addEventListener("dragover", (e) => e.preventDefault());
    window.addEventListener("drop", (e) => {
      e.preventDefault();
      dragCounter = 0;
      $("drop-overlay").classList.add("hidden");
      if (!state.unlocked) return;
      const file = e.dataTransfer?.files?.[0];
      if (file) decodeQrFile(file);
    });

    // Search
    $("search-friends").oninput = renderSidebar;

    // Chat actions
    $("btn-send").onclick = sendMessage;
    $("message-input").onkeydown = (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    };
    $("message-input").oninput = () => {
      if (!activeOnion) return;
      clearTimeout(typingTimer);
      api("/api/typing", { method: "POST", body: JSON.stringify({ onion: activeOnion, typing: true }) }).catch(() => {});
      typingTimer = setTimeout(() => {
        api("/api/typing", { method: "POST", body: JSON.stringify({ onion: activeOnion, typing: false }) }).catch(() => {});
      }, 2000);
    };

    // File Attachment (supports 4K video, photos, audio, and documents up to 1 GB)
    $("btn-attach").onclick = () => $("file-attach-input").click();
    $("file-attach-input").onchange = (e) => {
      const f = e.target.files[0];
      if (!f) return;
      if (f.size > 1024 * 1024 * 1024) {
        toast("File too large (max 1 GB).", true);
        return;
      }
      pendingAttachment = f;
      const sizeLabel = f.size >= 1024 * 1024
        ? `${(f.size / (1024 * 1024)).toFixed(1)} MB`
        : `${Math.max(1, Math.round(f.size / 1024))} KB`;
      $("attachment-name").textContent = `📎 ${f.name} (${sizeLabel})`;
      $("attachment-bar").classList.remove("hidden");
    };
    $("btn-clear-attachment").onclick = clearAttachment;

    // Verify & Remove Friend
    $("btn-verify-key").onclick = () => {
      const f = state.friends[activeOnion];
      if (!f) return;
      $("verify-peer-name").textContent = `${f.display_name} (@${f.username})`;
      $("verify-fp-code").textContent = f.fingerprint;
      $("verify-onion-full").textContent = "";
      $("modal-verify").classList.remove("hidden");
    };
    $("btn-remove-friend").onclick = async () => {
      if (!activeOnion) return;
      if (!confirm("Remove this friend and delete local chat history with them?")) return;
      await api("/api/friends/remove", { method: "POST", body: JSON.stringify({ onion: activeOnion }) });
      activeOnion = null;
      renderAll();
    };

    // Offline Emoji Picker
    const emojis = ["😀","😂","😍","🥳","😎","🤔","👍","🙏","🔥","❤️","🧅","🔒","🛡️","🎉","👀","💯","🚀","✨","🤝","👋","😅","😭","🤯","✅"];
    const picker = $("emoji-picker");
    emojis.forEach((em) => {
      const b = document.createElement("button");
      b.className = "emoji-btn";
      b.textContent = em;
      b.onclick = () => {
        $("message-input").value += em;
        picker.classList.add("hidden");
        $("message-input").focus();
      };
      picker.appendChild(b);
    });
    $("btn-emoji").onclick = () => picker.classList.toggle("hidden");
  }

  bindEvents();
  connectSSE();
})();
