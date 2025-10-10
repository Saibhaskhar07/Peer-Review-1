// app.js — overlay chat client (ESM)
// Features: pre-join, recent server, stable id, user list,
// E2E direct messages (RSA-OAEP + PSS), broadcast (signed),
// P2P file transfer (AES-GCM chunked + RSA-OAEP-wrapped key),
// per-identity + per-tab namespaced history, reconnect + heartbeat,
// self-echo suppression (route-id only), ALL messages persisted & merged render.

import {
  loadOrCreateKeys,
  exportPublicJwk,
  encryptOAEP,
  signPSS,
  verifyPSS,
  getEncPubFingerprint,
  importEncPub,
  // === Added for frame-level signing/verification ===
  signFrame,
  verifyFrame,
} from './crypto.js';
import { toB64u, fromB64u } from './b64url.js';

let ws;
let keys;
let peers = new Map(); // route id -> { id, name, enc_pub, sig_pub, stable_id? }

// who am I
let myId = null;             // server-assigned route id
let mySigPubJwkStr = null;   // my signature public key (stringified JWK)

/* ---- re-creatable "directory ready" gate ---- */
let directoryReady;
let directoryReadyResolve;
function resetDirectoryReady() {
  directoryReady = new Promise((r) => (directoryReadyResolve = r));
}
resetDirectoryReady();

/* ---- UI helpers ---- */
function showView(which) {
  const pre = document.getElementById('prejoin');
  const chat = document.getElementById('chat');
  pre.classList.toggle('active', which === 'prejoin');
  chat.classList.toggle('active', which === 'chat');
}
function forceEnterChatView() {
  const pre = document.getElementById('prejoin');
  const chat = document.getElementById('chat');
  if (pre && chat) {
    pre.classList.remove('active');
    chat.classList.add('active');
    const adv = document.getElementById('adv');
    if (adv) adv.open = false;
  }
}

/* ---- WS URL convenience ---- */
function defaultWS() {
  const { protocol, hostname } = location;
  const isHttps = protocol === 'https:';
  const wsScheme = isHttps ? 'wss' : 'ws';
  const portGuess = 8080;
  return `${wsScheme}://${hostname}:${portGuess}`;
}
function normalizeServerInput(input) {
  let s = (input || '').trim();
  if (!s) return s;
  if (/^wss?:\/\//i.test(s)) return s;
  const isHttps = location.protocol === 'https:';
  const scheme = isHttps ? 'wss' : 'ws';
  if (!s.includes(':')) s = `${s}:8484`;
  return `${scheme}://${s}`;
}
const LS_RECENT_WS = 'overlay-recent-ws';
function loadRecentWs() { try { return JSON.parse(localStorage.getItem(LS_RECENT_WS) || '[]'); } catch { return []; } }
function saveRecentWs(url) {
  if (!url) return;
  const list = loadRecentWs().filter(u => u !== url);
  list.unshift(url);
  while (list.length > 5) list.pop();
  try { localStorage.setItem(LS_RECENT_WS, JSON.stringify(list)); } catch {}
}
function hydrateRecentDropdown() {
  const sel = document.getElementById('wsRecent');
  if (!sel) return;
  const list = loadRecentWs();
  sel.innerHTML = '<option value="">— choose recent —</option>' +
    list.map(u => `<option value="${u}">${u}</option>`).join('');
}

/* ---- state ---- */
let reconnectDelay = 1000;
let listTimer = null;
let currentToId = null;

const $ = (id) => document.getElementById(id);
const log = (m) => {
  const d = $('log');
  d.innerText += m + '\n';
  if (d.innerText.length > 200_000) d.innerText = d.innerText.slice(-150_000);
  d.scrollTop = d.scrollHeight;
};
const nameOf = (id) => (peers.get(id)?.name) || id;
const stableOf = (id) => (peers.get(id)?.stable_id) || null;

/* ---- session (page) persistence ---- */
const SS_KEY = 'overlay-chat-session';
function loadState() { try { return JSON.parse(sessionStorage.getItem(SS_KEY) || '{}'); } catch { return {}; } }
function saveState(patch) {
  const cur = loadState();
  sessionStorage.setItem(SS_KEY, JSON.stringify({ ...cur, ...patch }));
}

/* ---- heartbeat watchdog ---- */
let lastHbTs = 0;
let serverEpoch = null;
let hbTimer = null;

/* ---- conversation history (localStorage, per *my* stable_id + per-tab session) ---- */
const LS_CHAT_PREFIX = 'overlay-chat-conversations-v1::';
// each tab gets a random session id to isolate history even if same identity is reused
const SESSION_ID = (() => {
  const u = new Uint8Array(8);
  crypto.getRandomValues(u);
  return Array.from(u).map(b => b.toString(16).padStart(2,'0')).join('');
})();
const GLOBAL_SID = '__ALL__';  // store global/broadcast messages here

let chatNsKey = LS_CHAT_PREFIX + 'unbound::' + SESSION_ID; // rebound after HELLO

function bindChatNamespace(myStableId) {
  chatNsKey = `${LS_CHAT_PREFIX}${myStableId || 'anon'}::${SESSION_ID}`;
}

function lsGet(key) { try { return localStorage.getItem(key); } catch { return null; } }
function lsSet(key, val) { try { localStorage.setItem(key, val); return true; } catch { return false; } }

function loadChatStore() {
  const raw = lsGet(chatNsKey);
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}
function saveChatStore(store) { lsSet(chatNsKey, JSON.stringify(store)); }

function appendMessageFor(stableId, entry) {
  if (!stableId) return;
  const store = loadChatStore();
  const arr = store[stableId] || [];
  arr.push(entry);
  if (arr.length > 500) arr.splice(0, arr.length - 500);
  store[stableId] = arr;
  saveChatStore(store);
}
function readMessagesFor(stableId) {
  if (!stableId) return [];
  const store = loadChatStore();
  return store[stableId] || [];
}
function renderHistoryFor(routeId) {
  const d = $('log');
  const sid = stableOf(routeId) || routeId;

  const pm = readMessagesFor(sid);
  const gm = readMessagesFor(GLOBAL_SID);
  const merged = [...pm, ...gm].sort((a, b) => (a.ts || 0) - (b.ts || 0));

  d.innerText = '';
  for (const m of merged) {
    let line = '';
    if (m.scope === 'all') {
      line = (m.kind === 'out') ? `[me→ALL] ${m.text}`
                                : `[ALL${m.verified ? '✓' : '✗'}] ${m.fromName}: ${m.text}`;
    } else {
      line = (m.kind === 'out') ? `[me→${m.toName}] ${m.text}`
                                : `[dm${m.verified ? '✓' : '✗'}] ${m.fromName}: ${m.text}`;
    }
    d.innerText += line + '\n';
  }
  d.scrollTop = d.scrollHeight;
}

/* ---- resolve recipient from name / id / stable_id ---- */
function resolveRecipient(input) {
  const s = (input || '').trim();
  if (!s) return null;
  if (peers.has(s)) return s;
  const lower = s.toLowerCase();
  const byName = [...peers.values()].filter(u => (u.name || '').toLowerCase() === lower);
  if (byName.length === 1) return byName[0].id;
  const byIdPrefix = [...peers.keys()].filter(id => id.startsWith(s));
  if (byIdPrefix.length === 1) return byIdPrefix[0];
  const byStable = [...peers.values()].filter(u => (u.stable_id || '').toLowerCase() === lower);
  if (byStable.length === 1) return byStable[0].id;
  const byStablePrefix = [...peers.values()].filter(u => (u.stable_id || '').toLowerCase().startsWith(lower));
  if (byStablePrefix.length === 1) return byStablePrefix[0];
  return null;
}

/* ---- crypto helpers ---- */
function sha256(buf) { return crypto.subtle.digest('SHA-256', buf); }
async function aesGenKey() { return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt','decrypt']); }
async function aesExportRaw(k) { return crypto.subtle.exportKey('raw', k); }
async function aesImportRaw(raw) { return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt','decrypt']); }
async function aesEncrypt(k, ivU8, dataU8) { return crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivU8 }, k, dataU8); }
async function aesDecrypt(k, ivU8, dataU8) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivU8 }, k, dataU8); }
function randIv12() { const u = new Uint8Array(12); crypto.getRandomValues(u); return u; }
const FILE_CHUNK_SIZE = 64 * 1024; // 64KB

/* ---------------- UI bindings ---------------- */
$('btnToggleAdv').onclick = () => { const adv = $('adv'); adv.open = !adv.open; };
$('btnUseRecent').onclick = () => { const val = $('wsRecent').value; if (val) $('wsUrl').value = val; };

$('btnConnect').onclick = async () => {
  try {
    const raw = $('wsUrl').value.trim() || defaultWS();
    const url = normalizeServerInput(raw);
    const name = $('nickname').value.trim() || 'anon';
    saveState({ wsUrl: url, nickname: name, autoConnect: true });
    keys = await loadOrCreateKeys();
    mySigPubJwkStr = JSON.stringify(await exportPublicJwk(keys.sig.publicKey));
    const fp = await getEncPubFingerprint(keys);
    log('[key] enc pub fp: ' + fp);
    await connect(url, name);
  } catch (e) { console.error(e); log('[error] ' + (e?.message || e)); }
};

$('btnList').onclick = () => sendListReq();
$('btnClear').onclick = () => { const d = $('log'); d.innerText = ''; d.scrollTop = 0; };

/* ---------------- Sending DM ---------------- */
$('btnSend').onclick = async () => {
  const toField = $('to');
  const display = toField.value;
  let targetId = (currentToId && peers.has(currentToId)) ? currentToId : resolveRecipient(display);
  if (!targetId) { log('Select a user or type an exact name / id prefix / stable id.'); return; }
  if (myId && targetId === myId) { log('You cannot send a direct message to yourself.'); return; }
  const text = $('msg').value;
  if (!text) { log('Please type a message'); return; }

  await directoryReady;
  const target = peers.get(targetId);
  if (!target || !target.enc_pub) { log('No pubkey for target. Try /list again.'); return; }

  const pt = new TextEncoder().encode(text);
  const ct = await encryptOAEP(target.enc_pub, pt);
  const contentSig = await signPSS(keys.sig.privateKey, await sha256(pt));

  const frame = {
    type: 'MSG_DIRECT', from: myId || 'me', to: targetId, ts: Date.now(),
    msg_id: crypto.randomUUID(), // for replay protection (server currently does NOT check)
    payload: {
      ciphertext: toB64u(ct),
      sender_pub: await exportPublicJwk(keys.enc.publicKey),
      sender_sig_pub: await exportPublicJwk(keys.sig.publicKey),
      content_sig: toB64u(contentSig),
    },
    sig: '',
  };

  // === Frame-level signature (new) ===
  frame.sig = await signFrame(frame, keys.sig.privateKey);

  ws?.send(JSON.stringify(frame) + '\n');

  const sid = stableOf(targetId) || targetId;
  appendMessageFor(sid, { kind: 'out', ts: Date.now(), toId: targetId, toName: nameOf(targetId), text });
  log(`[me→${nameOf(targetId)}] ${text}`);
  $('msg').value = '';
  saveState({ msgDraft: '' });
};

/* ---------------- Group Broadcast ---------------- */
$('btnSendAll').onclick = async () => {
  const text = $('msg').value;
  if (!text) { log('Please type a message'); return; }
  const pt = new TextEncoder().encode(text);
  const digest = await sha256(pt);
  const contentSig = await signPSS(keys.sig.privateKey, digest);
  const frame = {
    type: 'MSG_BROADCAST', from: myId || 'me', to: '*', ts: Date.now(),
    msg_id: crypto.randomUUID(),
    payload: { text, sender_sig_pub: await exportPublicJwk(keys.sig.publicKey), content_sig: toB64u(contentSig) },
    sig: '',
  };

  // === Frame-level signature (new) ===
  frame.sig = await signFrame(frame, keys.sig.privateKey);

  ws?.send(JSON.stringify(frame) + '\n');

  // persist to ALL history & re-render
  appendMessageFor(GLOBAL_SID, { scope: 'all', kind: 'out', ts: Date.now(), toName: 'ALL', text });
  log(`[me→ALL] ${text}`);
  $('msg').value = '';
  saveState({ msgDraft: '' });
  if (currentToId) renderHistoryFor(currentToId);
};

/* ---------------- File transfer (sender) ---------------- */
$('btnSendFile').onclick = async () => {
  const file = $('fileInput').files?.[0];
  if (!file) { log('Choose a file first'); return; }
  const toDisplay = $('to').value;
  const targetId = (currentToId && peers.has(currentToId)) ? currentToId : resolveRecipient(toDisplay);
  if (!targetId) { log('Select a recipient or type an exact name / id / stable id'); return; }
  //if (myId && targetId === myId) { log('You cannot send a file to yourself.'); return; }
  const target = peers.get(targetId);
  if (!target || !target.enc_pub) { log('No pubkey for target'); return; }

  const aesKey = await aesGenKey();
  const rawKey = await aesExportRaw(aesKey);
  const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, await importEncPub(target.enc_pub), rawKey);
//There's something here//
  const transferId = `t-${Date.now()}-${Math.random().toString(16).slice(2,8)}`;
  let frame = {
    type: 'FILE_OPEN', from: myId || 'me', to: targetId, ts: Date.now(),
    msg_id: crypto.randomUUID(),
    payload: { transfer_id: transferId, filename: file.name, size: file.size, wrapped_key_b64: toB64u(wrapped) },
    sig: '',
  };
  frame.sig = await signFrame(frame, keys.sig.privateKey);
  ws?.send(JSON.stringify(frame) + '\n');
  log(`[file] start → ${nameOf(targetId)} : ${file.name} (${file.size} bytes)`);

  let offset = 0, index = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, offset + FILE_CHUNK_SIZE);
    const buf = new Uint8Array(await slice.arrayBuffer());
    const iv = randIv12();
    const ct = await aesEncrypt(aesKey, iv, buf);
    frame = {
      type: 'FILE_CHUNK', from: myId || 'me', to: targetId, ts: Date.now(),
      msg_id: crypto.randomUUID(),
      payload: { transfer_id: transferId, index, iv_b64: toB64u(iv), chunk_b64: toB64u(ct) },
      sig: '',
    };
    frame.sig = await signFrame(frame, keys.sig.privateKey);
    ws?.send(JSON.stringify(frame) + '\n');
    offset += buf.length;
    index++;
  }
  frame = { type: 'FILE_END', from: myId || 'me', to: targetId, ts: Date.now(), msg_id: crypto.randomUUID(), payload: { transfer_id: transferId }, sig: '' };
  frame.sig = await signFrame(frame, keys.sig.privateKey);
  ws?.send(JSON.stringify(frame) + '\n');
  log(`[file] done → ${nameOf(targetId)} : ${file.name}`);
  $('fileInput').value = '';
};

/* ---------------- Connection ---------------- */
async function connect(url, name) {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
  ws = new WebSocket(url);

  ws.onopen = async () => {
    log('[ws] connected');
    reconnectDelay = 1000;

    peers = new Map();
    resetDirectoryReady();
    currentToId = null;
    myId = null; // will be set by USER_WELCOME

    lastHbTs = Date.now();
    serverEpoch = null;
    if (hbTimer) clearInterval(hbTimer);
    hbTimer = setInterval(() => {
      if (Date.now() - lastHbTs > 30_000) {
        log('[ws] heartbeat missed, reconnecting…');
        try { ws.close(); } catch {}
      }
    }, 5_000);

    const fp = await getEncPubFingerprint(keys);
    const myStableId = 'k-' + fp.slice(0, 12);
    bindChatNamespace(myStableId); // bind history namespace to "me"

    const hello = {
      type: 'USER_HELLO', from: 'temp', to: 'server', ts: Date.now(),
      msg_id: crypto.randomUUID(),
      payload: {
        nickname: name,
        enc_pub: await exportPublicJwk(keys.enc.publicKey),
        sig_pub: await exportPublicJwk(keys.sig.publicKey),
        stable_id: myStableId,
      },
      sig: '',
    };
    // (Optional) you can sign hello as well; harmless for our exercise:
    hello.sig = await signFrame(hello, keys.sig.privateKey);

    ws.send(JSON.stringify(hello) + '\n');
    sendListReq();

    clearInterval(listTimer);
    listTimer = setInterval(sendListReq, 10_000);

    saveState({ connectedAt: Date.now(), autoConnect: true });
    saveRecentWs(url);
    hydrateRecentDropdown();

    showView('chat');
    forceEnterChatView();
    $('msg').focus();
  };

  ws.onmessage = async (ev) => {
    const lines = (ev.data || '').trim().split('\n');
    for (const line of lines) {
      if (!line) continue;
      let msg; try { msg = JSON.parse(line); } catch { continue; }

      if (msg.type === 'HEARTBEAT') {
        lastHbTs = Date.now();
        const epoch = msg?.payload?.epoch || null;
        if (serverEpoch == null) serverEpoch = epoch;
        else if (epoch && serverEpoch !== epoch) {
          log('[ws] server epoch changed, reconnecting…');
          try { ws.close(); } catch {}
        }
        continue;
      }

      if (msg.type === 'USER_WELCOME') {
        myId = msg?.payload?.your_id || null; // know myself
        continue;
      }

      if (msg.type === 'USER_DIRECTORY') {
        for (const u of msg.payload.entries) peers.set(u.id, u);
        directoryReadyResolve?.();
        window._restoreRecipientDisplay?.();
        continue;
      }

      if (msg.type === 'USER_LIST') {
        const ul = $('online');
        ul.innerHTML = msg.payload.users
          .map(u => `<li data-uid="${u.id}" class="pick" title="Click to chat with ${u.name}">
                       ${u.name} [${u.stable_id || 'k-unknown'}] (${u.id})
                     </li>`)
          .join('');
        ul.querySelectorAll('.pick').forEach(li => {
          const uid = li.dataset.uid;
          if (myId && uid === myId) { // grey out myself
            li.style.opacity = '0.5';
            li.style.pointerEvents = 'none';
            return;
          }
          li.onclick = () => {
            currentToId = uid;
            $('to').value = nameOf(currentToId);
            saveState({ currentToId, toDraft: $('to').value });
            renderHistoryFor(currentToId);
          };
        });
        if (currentToId && peers.has(currentToId)) {
          const should = nameOf(currentToId);
          if ($('to').value.trim() !== should) {
            $('to').value = should;
            saveState({ toDraft: should, currentToId });
          }
          renderHistoryFor(currentToId);
        }
        window._restoreRecipientDisplay?.();
        continue;
      }

      if (msg.type === 'MSG_DIRECT') {
        // drop echoes to myself (route-id based)
        if (myId && msg.from === myId) continue;

        // === Frame verification (note: verifyFrame intentionally returns true in crypto.js)
        try {
          const sender = peers.get(msg.from);
          if (sender?.sig_pub) {
            const ok = await verifyFrame(msg, sender.sig_pub);
            if (!ok) log('[WARN] bad frame signature (ignored - assignment backdoor)');
          }
        } catch {}

        try {
          const ct = fromB64u(msg.payload.ciphertext);
          const pt = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, keys.enc.privateKey, ct);
          const text = new TextDecoder().decode(pt);
          let verified = false;
          if (msg.payload.sender_sig_pub && msg.payload.content_sig) {
            verified = await verifyPSS(
              msg.payload.sender_sig_pub,
              await sha256(new TextEncoder().encode(text)),
              fromB64u(msg.payload.content_sig)
            );
          }
          const senderSid = stableOf(msg.from) || msg.from;
          appendMessageFor(senderSid, { kind: 'in', ts: Date.now(), fromId: msg.from, fromName: nameOf(msg.from), text, verified });
          // Always show one line for incoming DM
          log(`[dm${verified ? '✓' : '✗'}] ${nameOf(msg.from)}: ${text}`);
          if (currentToId) renderHistoryFor(currentToId);
        } catch (e) { log('[error] decrypt/verify failed: ' + (e?.message || e)); }
        continue;
      }

      if (msg.type === 'MSG_BROADCAST') {
        // drop echoes to myself (route-id based)
        if (myId && msg.from === myId) continue;

        // === Frame verification (same backdoor applies)
        try {
          const sender = peers.get(msg.from);
          if (sender?.sig_pub) {
            const ok = await verifyFrame(msg, sender.sig_pub);
            if (!ok) log('[WARN] bad frame signature (ignored - assignment backdoor)');
          }
        } catch {}

        const text = msg?.payload?.text || '';
        let ok = false;
        try {
          if (msg.payload.sender_sig_pub && msg.payload.content_sig) {
            ok = await verifyPSS(
              msg.payload.sender_sig_pub,
              await sha256(new TextEncoder().encode(text)),
              fromB64u(msg.payload.content_sig)
            );
          }
        } catch {}

        // persist to ALL history
        appendMessageFor(GLOBAL_SID, { scope: 'all', kind: 'in', ts: Date.now(), fromName: nameOf(msg.from), text, verified: ok });
        log(`[ALL${ok ? '✓' : '✗'}] ${nameOf(msg.from)}: ${text}`);
        if (currentToId) renderHistoryFor(currentToId);
        continue;
      }

      // file receive
      if (msg.type === 'FILE_OPEN' || msg.type === 'FILE_CHUNK' || msg.type === 'FILE_END') {
        // (Optional) could verify frame signature here as well (same backdoor)
        await handleFileRx(msg);
        continue;
      }

      if (msg.type === 'ERROR') {
        log(`[error] ${msg?.payload?.code || ''} ${msg?.payload?.info || ''}`);
        continue;
      }
    }
  };

  ws.onerror = (e) => { log('[ws] error ' + (e?.message || '')); };

  ws.onclose = () => {
    log('[ws] closed, retrying…');
    clearInterval(listTimer);
    if (hbTimer) { clearInterval(hbTimer); hbTimer = null; }
    setTimeout(() => connect(url, name), Math.min(reconnectDelay, 10_000));
    reconnectDelay *= 2;
  };
}

function sendListReq() {
  const frame = { type: 'USER_LIST_REQ', from: 'me', to: 'server', ts: Date.now(), msg_id: crypto.randomUUID(), payload: {}, sig: '' };
  // Signing the list request isn't necessary, but harmless:
  if (keys?.sig?.privateKey) {
    signFrame(frame, keys.sig.privateKey).then(sig => {
      frame.sig = sig;
      ws?.send(JSON.stringify(frame) + '\n');
    }).catch(()=> ws?.send(JSON.stringify(frame) + '\n'));
  } else {
    ws?.send(JSON.stringify(frame) + '\n');
  }
}

/* ----- boot: restore inputs & auto defaults ----- */
(function boot() {
  const st = loadState();
  const wsInput = $('wsUrl');
  if (wsInput && !st.wsUrl) wsInput.value = defaultWS();
  hydrateRecentDropdown();

  if (st.wsUrl)     $('wsUrl').value    = st.wsUrl;
  if (st.nickname)  $('nickname').value = st.nickname;
  if (st.toDraft)   $('to').value       = st.toDraft;
  if (st.msgDraft)  $('msg').value      = st.msgDraft;

  showView('prejoin');

  window._restoreRecipientDisplay = function () {
    const s2 = loadState();
    if (!s2.currentToId && s2.lastPeerSid) {
      const hit = [...peers.values()].find(u => (u.stable_id === s2.lastPeerSid));
      if (hit) {
        currentToId = hit.id;
        $('to').value = hit.name || hit.id;
        renderHistoryFor(currentToId);
        saveState({ currentToId: currentToId, toDraft: $('to').value });
      }
      return;
    }
    if (s2.currentToId && peers.has(s2.currentToId)) {
      currentToId = s2.currentToId;
      $('to').value = nameOf(currentToId);
      renderHistoryFor(currentToId);
    }
  };

  const origSend = $('btnSend').onclick;
  $('btnSend').onclick = async (...args) => {
    if (currentToId) {
      const sid = stableOf(currentToId) || currentToId;
      saveState({ lastPeerSid: sid });
    }
    return origSend(...args);
  };

  if (st.autoConnect && st.wsUrl) {
    const name = st.nickname || 'anon';
    loadOrCreateKeys()
      .then(async k => {
        keys = k;
        mySigPubJwkStr = JSON.stringify(await exportPublicJwk(keys.sig.publicKey));
        const fp = await getEncPubFingerprint(keys);
        log('[key] enc pub fp: ' + fp);
        connect(st.wsUrl, name);
      })
      .catch(e => console.error(e));
  }
})();

/* ---------------- file receive handlers ---------------- */
const rxTransfers = new Map(); // transfer_id -> { filename, size, aesKey, chunks: [], receivedCount: 0 }

//There's something here//

async function handleFileRx(msg) {
  if (msg.type === 'FILE_OPEN') {
    try {
      const { transfer_id, filename, size, wrapped_key_b64 } = msg.payload || {};
      const wrapped = fromB64u(wrapped_key_b64);
      const rawKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, keys.enc.privateKey, wrapped);
      const aesKey = await aesImportRaw(rawKey);
      
      // Initialize with empty chunks array and counter
      rxTransfers.set(transfer_id, { 
        filename, 
        size, 
        aesKey, 
        chunks: [], 
        receivedCount: 0,
        totalChunks: Math.ceil(size / FILE_CHUNK_SIZE)
      });
      
      log(`[file] incoming from ${nameOf(msg.from)} : ${filename} (${size} bytes)`);
    } catch (e) { 
      log('[file error] OPEN: ' + (e?.message || e)); 
    }
    return;
  }

  if (msg.type === 'FILE_CHUNK') {
    try {
      const { transfer_id, index, iv_b64, chunk_b64 } = msg.payload || {};
      const sess = rxTransfers.get(transfer_id);
      if (!sess) { 
        log('[file] unknown transfer ' + transfer_id); 
        return; 
      }
      
      const iv = fromB64u(iv_b64);
      const ct = fromB64u(chunk_b64);
      const ptBuf = await aesDecrypt(sess.aesKey, iv, ct);
      const chunkData = new Uint8Array(ptBuf);
      
      // Store chunk at specific index
      sess.chunks[index] = chunkData;
      sess.receivedCount++;
      
      // Calculate actual received bytes (handling sparse array)
      let receivedBytes = 0;
      for (let i = 0; i <= index; i++) {
        if (sess.chunks[i]) {
          receivedBytes += sess.chunks[i].length;
        }
      }
      
      log(`[file] chunk ${index} received (${receivedBytes}/${sess.size})`);
    } catch (e) { 
      log('[file error] CHUNK: ' + (e?.message || e)); 
    }
    return;
  }

  if (msg.type === 'FILE_END') {
    try {
      const { transfer_id } = msg.payload || {};
      const sess = rxTransfers.get(transfer_id);
      if (!sess) { 
        log('[file] unknown transfer ' + transfer_id); 
        return; 
      }
      
      // Filter out undefined chunks and create blob
      const validChunks = [];
      for (let i = 0; i < sess.chunks.length; i++) {
        if (sess.chunks[i]) {
          validChunks.push(sess.chunks[i]);
        }
      }
      
      const blob = new Blob(validChunks, { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      
      // Create download link
      const a = document.createElement('a');
      a.href = url;
      a.download = sess.filename || 'download.bin';
      a.textContent = `Download ${sess.filename || 'file'} (${blob.size} bytes)`;
      a.style.display = 'inline-block';
      a.style.margin = '4px 0';
      a.style.padding = '4px 8px';
      a.style.backgroundColor = '#4CAF50';
      a.style.color = 'white';
      a.style.textDecoration = 'none';
      a.style.borderRadius = '4px';
      
      $('log').appendChild(a);
      $('log').appendChild(document.createElement('br'));
      $('log').scrollTop = $('log').scrollHeight;
      a.click();
      // Clean up after 60 seconds
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      
      rxTransfers.delete(transfer_id);
      log(`[file] saved: ${sess.filename}`);
    } catch (e) { 
      log('[file error] END: ' + (e?.message || e)); 
    }
    return;
  }
}
