// mock-server.js — WebSocket mock server (ESM)
// Install: npm i ws nanoid
// Run:    node mock-server.js   (package.json should include "type":"module")

import { WebSocketServer } from 'ws';
import { nanoid } from 'nanoid';

const PORT = Number(process.env.PORT || 8484);
const wss = new WebSocketServer({ port: PORT });

// userId -> { id, name, enc_pub, sig_pub, stable_id, ws }
const users = new Map();

function send(ws, obj) {
  try { ws.send(JSON.stringify(obj) + '\n'); }
  catch (e) { console.error('[send error]', e); }
}

function buildDirectoryPayload() {
  return {
    entries: [...users.values()].map(u => ({
      id: u.id,
      name: u.name,
      enc_pub: u.enc_pub,
      sig_pub: u.sig_pub,
      stable_id: u.stable_id || null,
    })),
  };
}

function broadcastDirectory() {
  const frame = {
    type: 'USER_DIRECTORY',
    from: 'server', to: '*', ts: Date.now(),
    payload: buildDirectoryPayload(), sig: '',
  };
  for (const u of users.values()) send(u.ws, frame);
}

function broadcastUserList() {
  const payload = {
    users: [...users.values()].map(u => ({
      id: u.id,
      name: u.name,
      stable_id: u.stable_id || null,
    })),
  };
  const frame = { type: 'USER_LIST', from: 'server', to: '*', ts: Date.now(), payload, sig: '' };
  for (const u of users.values()) send(u.ws, frame);
}

function sendError(ws, code, info = '') {
  send(ws, { type: 'ERROR', from: 'server', to: 'me', ts: Date.now(), payload: { code, info }, sig: '' });
}

//Heartbeat with server epoch//
const SERVER_EPOCH = nanoid(6);

function broadcastHeartbeat() {
  const frame = {
    type: 'HEARTBEAT',
    from: 'server',
    to: '*',
    ts: Date.now(),
    payload: { epoch: SERVER_EPOCH },
    sig: '',
  };
  for (const u of users.values()) send(u.ws, frame);
}
setInterval(broadcastHeartbeat, 10_000);


wss.on('connection', (ws, req) => {
  const remote = req?.socket?.remoteAddress || 'unknown';
  console.log('[CONN]', remote);
  let myId = null;

  // immediate heartbeat to help clients lock epoch
  send(ws, { type: 'HEARTBEAT', from: 'server', to: 'me', ts: Date.now(), payload: { epoch: SERVER_EPOCH }, sig: '' });

  ws.on('message', (data) => {
    const text = data.toString().trim();
    const lines = text.split('\n');
    for (const line of lines) {
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { return sendError(ws, 'INVALID_JSON'); }
      const { type, payload } = msg || {};

      if (type === 'USER_HELLO') {
        myId = nanoid(10);
        const name = payload?.nickname || ('user_' + myId);
        users.set(myId, {
          id: myId,
          name,
          ws,
          enc_pub: payload?.enc_pub || null,
          sig_pub: payload?.sig_pub || null,
          stable_id: payload?.stable_id || null,
        });
        send(ws, {
         type: 'USER_WELCOME',
         from: 'server',
         to: myId,
         ts: Date.now(),
         payload: { your_id: myId },
         sig: ''
       });

        // send full directory to the newcomer
        send(ws, { type: 'USER_DIRECTORY', from: 'server', to: myId, ts: Date.now(),
                   payload: buildDirectoryPayload(), sig: '' });

        // broadcast updated directory + list to everyone
        broadcastDirectory();
        broadcastUserList();

        console.log(`[JOIN] ${name} (${myId}) online, total=${users.size}`);
        return;
      }

      if (type === 'USER_LIST_REQ') {
        send(ws, { type: 'USER_LIST', from: 'server', to: myId || 'me', ts: Date.now(),
                   payload: { users: [...users.values()].map(u => ({ id: u.id, name: u.name, stable_id: u.stable_id || null })) }, sig: '' });
        send(ws, { type: 'USER_DIRECTORY', from: 'server', to: myId || 'me', ts: Date.now(),
                   payload: buildDirectoryPayload(), sig: '' });
        return;
      }

      if (type === 'MSG_DIRECT') {
        const to = msg?.to;
        if (!to || !users.has(to)) return sendError(ws, 'USER_NOT_FOUND', String(to));
        const target = users.get(to);
        const deliver = { type: 'MSG_DIRECT', from: myId || 'unknown', to, ts: Date.now(),
                          payload: msg.payload, sig: msg.sig || '' };
        send(target.ws, deliver);
        return;
      }

      // broadcast to all
      if (type === 'MSG_BROADCAST') {
        const deliver = { type: 'MSG_BROADCAST', from: myId || 'unknown', to: '*', ts: Date.now(),
                          payload: msg.payload, sig: msg.sig || '' };
        for (const u of users.values()) {
          if (u.id === myId) continue; // uncomment to skip sender echo
          send(u.ws, deliver);
        }
        return;
      }

      // point-to-point file transfer frames
      if (type === 'FILE_OPEN' || type === 'FILE_CHUNK' || type === 'FILE_END') {
        const to = msg?.to;
        if (!to || !users.has(to)) return sendError(ws, 'USER_NOT_FOUND', String(to));
        const target = users.get(to);
        const deliver = { type, from: myId || 'unknown', to, ts: Date.now(),
                          payload: msg.payload, sig: msg.sig || '' };
        send(target.ws, deliver);
        return;
      }

      return sendError(ws, 'UNKNOWN_TYPE', type);
    }
  });

  ws.on('close', () => {
    if (!myId) return;
    const u = users.get(myId);
    users.delete(myId);
    broadcastDirectory();
    broadcastUserList();
    console.log(`[LEAVE] ${u?.name || myId} offline, total=${users.size}`);
  });

  ws.on('error', (e) => console.warn('[WS error]', e?.message || e));
});

console.log(`Mock WS server listening on ws://localhost:${PORT}`);
