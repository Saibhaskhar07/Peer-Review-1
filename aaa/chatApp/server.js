// server.js — overlay chat server (vulnerable version + heartbeat)
// 依然保留课程用漏洞：不验签 / 不做重放；仅补上心跳，防止前端定时重连。
// 下面加了“FIX-A/FIX-B”实现真正的验签和防重放。
// 如果需要仍然演示“有漏洞版本”，可切换 `ENFORCE_VERIFY` / `ENFORCE_REPLAY_PROTECTION` 为 false。

import crypto from 'crypto';
import express from 'express';
import http from 'http';
import { WebSocketServer } from 'ws';
import { nanoid } from 'nanoid';
import path from 'path';
import { fileURLToPath } from 'url';

const PORT = process.env.PORT || 8080;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// 静态资源：直接访问 http://localhost:8080/
app.use(express.static(path.join(__dirname, 'client')));
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'index.html'));
});

// 连接的用户：id -> { ws, name, enc_pub, sig_pub, stable_id }
const users = new Map();

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj) + '\n');
}
function broadcast(obj) {
  const data = JSON.stringify(obj) + '\n';
  for (const u of users.values()) {
    if (u.ws.readyState === u.ws.OPEN) u.ws.send(data);
  }
}
function pushDirectory() {
  const entries = [...users.entries()].map(([id, u]) => ({
    id, name: u.name, enc_pub: u.enc_pub, sig_pub: u.sig_pub, stable_id: u.stable_id
  }));
  broadcast({ type: 'USER_DIRECTORY', payload: { entries } });
}
function now() { return Date.now(); }

// 心跳包：客户端 30s 内收不到心跳会自断重连，这里每 10s 群发一次。 

const SERVER_EPOCH = Date.now().toString(); // 重启后改变，用来触发客户端重连
setInterval(() => {
  broadcast({ type: 'HEARTBEAT', payload: { epoch: SERVER_EPOCH, ts: now() } });
}, 10_000);

//安全增强选项（可切换）
//开关可以控制是否启用增强功能
const ENFORCE_VERIFY = true;
const ENFORCE_REPLAY_PROTECTION = true;

// FIX-A: 验签工具 
// 允许 JWK 或 PEM 两种形式的 sig_pub；自动识别并构造 Node 公钥
function toPublicKey(sig_pub) {
  if (!sig_pub) throw new Error('NO_SIG_PUB');
  if (typeof sig_pub === 'string') {
    // PEM
    return crypto.createPublicKey(sig_pub);
  }
  // JWK
  return crypto.createPublicKey({ key: sig_pub, format: 'jwk' });
}

// 和前端一致：签名覆盖 {type,from,to,ts,payload} 的 JSON
function verifySignature(sig_pub, msg) {
  const pub = toPublicKey(sig_pub);
  const dataBuf = Buffer.from(JSON.stringify({
    type: msg.type,
    from: msg.from,
    to: msg.to,
    ts: msg.ts,
    payload: msg.payload
  }), 'utf8');
  const sigBuf = Buffer.from(String(msg.sig || ''), 'base64');
  return crypto.verify('sha256', dataBuf, {
    key: pub,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32
  }, sigBuf);
}

// FIX-B: 防重放（最近 msg_id 集）
const recentMsgIds = new Map(); // routeId -> Set<msg_id>
function isUuidV4(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
}
function markAndCheckReplay(routeId, msg_id) {
  const seen = recentMsgIds.get(routeId) || new Set();
  if (seen.has(msg_id)) return true; // replay
  seen.add(msg_id);
  while (seen.size > 1000) { seen.delete(seen.values().next().value); } // 简单裁剪
  recentMsgIds.set(routeId, seen);
  return false;
}

// FIX-A/B: 统一校验入口 
// 对需要保护的类型先做字段检查、UUID 格式、去重与验签
function needsProtection(type) {
  return type === 'MSG_DIRECT' || type === 'MSG_BROADCAST' ||
         type === 'FILE_OPEN'  || type === 'FILE_CHUNK'    || type === 'FILE_END';
}
function hasRequiredFields(msg) {
  const required = ['type', 'from', 'to', 'ts', 'payload', 'sig', 'msg_id'];
  for (const k of required) {
    if (!(k in msg)) return k;
  }
  return null;
}

wss.on('connection', (ws) => {
  const myId = nanoid();
  users.set(myId, { ws, name: `user-${myId}`, enc_pub: null, sig_pub: null, stable_id: null });

  console.log(`[server] client ${myId} connected`);
  send(ws, { type: 'USER_WELCOME', payload: { your_id: myId } });
  pushDirectory();

  ws.on('message', async (raw) => {
    const lines = raw.toString().split('\n').filter(Boolean);
    for (const line of lines) {
      let msg; try { msg = JSON.parse(line); } catch { continue; }
      const type = msg?.type;

      // FIX-0: 统一将“可伪造的 from”覆盖为真实连接 ID，防止跨会话冒充
      msg.from = myId;

      // FIX-A/B: 对敏感帧做必要校验
      if (needsProtection(type)) {
        // 1) 基本字段
        const missing = hasRequiredFields(msg);
        if (missing) {
          send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
            payload: { code: 'MALFORMED_FRAME', info: missing }, sig: '' });
          continue;
        }

        // 2) msg_id (UUID v4) & 去重
        if (ENFORCE_REPLAY_PROTECTION) {
          if (!isUuidV4(String(msg.msg_id || ''))) {
            send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
              payload: { code: 'INVALID_MSG_ID' }, sig: '' });
            continue;
          }
          const isReplay = markAndCheckReplay(myId, msg.msg_id);
          if (isReplay) {
            send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
              payload: { code: 'REPLAYED_MSG' }, sig: '' });
            continue;
          }
        }

        // 3) 验签（RSA-PSS/SHA-256/saltLen=32）
        if (ENFORCE_VERIFY) {
          try {
            const sender = users.get(myId);
            const ok = verifySignature(sender?.sig_pub, msg);
            if (!ok) {
              send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
                payload: { code: 'INVALID_SIG' }, sig: '' });
              continue;
            }
          } catch (e) {
            const info = (e && e.message) ? e.message : String(e);
            send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
              payload: { code: 'SIG_VERIFY_ERROR', info }, sig: '' });
            continue;
          }
        }
      }

      const u = users.get(myId);
      const to = msg?.to;

      if (type === 'USER_HELLO') {
        // 存储客户端提供的身份信息（此处未验证签名/密钥合法性）
        // FIX-INFO: 如果需要强制检查 JWK/PEM 强度，可在此处解析并拒绝弱钥（如 < 4096 位）
        if (u) {
          u.name = msg.payload?.nickname || u.name;
          u.enc_pub = msg.payload?.enc_pub || null;
          u.sig_pub = msg.payload?.sig_pub || null; // FIX-A 依赖：后续验签会用到
          u.stable_id = msg.payload?.stable_id || null;
        }
        pushDirectory();
        continue;
      }

      if (type === 'USER_LIST_REQ') {
        const list = [...users.entries()].map(([id, u2]) => ({
          id, name: u2.name, stable_id: u2.stable_id
        }));
        send(ws, { type: 'USER_LIST', payload: { users: list } });
        continue;
      }

      if (type === 'MSG_DIRECT') {
        // VULN-A: 不验证帧签名  VULN-B: 不检查 msg_id（无重放保护）
        //在 ENFORCE_* 为 true 时，前面已经做了验签和去重。
        const target = users.get(to);
        if (target && target.ws.readyState === target.ws.OPEN) {
          send(target.ws, { ...msg, from: myId, ts: now() });
        } else {
          send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
            payload: { code: 'NO_SUCH_USER', info: String(to) }, sig: '' });
        }
        continue;
      }

      if (type === 'MSG_BROADCAST') {
        // 同样不验签/不防重放（教学用漏洞）
        // 在 ENFORCE_* 打开时，已在上面统一校验。
        broadcast({ ...msg, from: myId, ts: now() });
        continue;
      }

      // server.js 第104-110行
      if (type === 'FILE_OPEN' || type === 'FILE_CHUNK' || type === 'FILE_END') {
        // 这里仍然走“转发”模式；若需进一步严格：可检查 index 连续性、总大小/摘要等
        const target = users.get(to);
        if (target && target.ws.readyState === target.ws.OPEN) {
          send(target.ws, { ...msg, from: myId, ts: now() });
        } else {
          send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
            payload: { code: 'NO_SUCH_USER', info: String(to) }, sig: '' });
        }
        continue;
      }

      // 未识别类型：回错误
      if (!type) {
        send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
          payload: { code: 'MALFORMED_FRAME', info: 'missing type' }, sig: '' });
      } else {
        send(ws, { type: 'ERROR', from: 'server', to: myId, ts: now(),
          payload: { code: 'UNKNOWN_TYPE', info: String(type) }, sig: '' });
      }
    }
  });

  ws.on('close', () => {
    users.delete(myId);
    console.log(`[server] client ${myId} disconnected`);
    pushDirectory();
  });
});

server.listen(PORT, () => {
  console.log(`[server] running on http://localhost:${PORT}`);
});
