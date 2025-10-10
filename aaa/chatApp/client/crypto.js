// crypto.js — stable key reuse: in-memory cache + localStorage (if available)
// Also exposes getEncPubFingerprint() to verify keys are unchanged.
// Works in secure contexts only (https, or http://localhost)

const subtle = (globalThis.crypto && globalThis.crypto.subtle) || null;

function assertSecure() {
  if (!subtle) {
    const why = self.isSecureContext
      ? 'WebCrypto is not supported by this browser'
      : 'This page is not a secure context (use https or http://localhost)';
    throw new Error('WebCrypto unavailable: ' + why);
  }
}

const PUBEXP = new Uint8Array([1, 0, 1]);
const LS_KEY = 'demo-rsa-keypair-jwk';

//  in-memory cache to avoid regenerating within a session 
let _cachedKeys = null;

//  safe localStorage helpers (won’t throw in restricted modes) 
function lsGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function lsSet(key, val) {
  try { localStorage.setItem(key, val); return true; } catch { return false; }
}
function lsRemove(key) {
  try { localStorage.removeItem(key); } catch {}
}

//  generate RSA-OAEP (encrypt/decrypt) and RSA-PSS (sign/verify) keys 
export async function genKeys() {
  assertSecure();
  const enc = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 4096, publicExponent: PUBEXP, hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  const sig = await subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 4096, publicExponent: PUBEXP, hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  return { enc, sig };
}

//  key import/export helpers 
export async function exportPublicJwk(pubKey) {
  return subtle.exportKey('jwk', pubKey);
}
export async function exportPrivateJwk(privKey) {
  return subtle.exportKey('jwk', privKey);
}

export async function importEncPub(jwk) {
  return subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
}
export async function importSigPub(jwk) {
  return subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify']);
}
export async function importEncPriv(jwk) {
  return subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}
export async function importSigPriv(jwk) {
  return subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign']);
}

//  basic crypto helpers 
export async function encryptOAEP(jwkPub, plaintextU8) {
  const pub = await importEncPub(jwkPub);
  return subtle.encrypt({ name: 'RSA-OAEP' }, pub, plaintextU8);
}
export async function signPSS(privKey, dataBuffer) {
  return subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privKey, dataBuffer);
}
export async function verifyPSS(jwkPub, dataBuffer, sigBuf) {
  const pub = await importSigPub(jwkPub);
  return subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, sigBuf, dataBuffer);
}

//  persistence with fallback 
export async function loadOrCreateKeys() {
  assertSecure();
  if (_cachedKeys) return _cachedKeys;

  const cached = lsGet(LS_KEY);
  if (cached) {
    try {
      const j = JSON.parse(cached);
      const enc = {
        publicKey: await importEncPub(j.enc_pub),
        privateKey: await importEncPriv(j.enc_priv),
      };
      const sig = {
        publicKey: await importSigPub(j.sig_pub),
        privateKey: await importSigPriv(j.sig_priv),
      };
      _cachedKeys = { enc, sig };
      return _cachedKeys;
    } catch {
      // corrupted storage, fall through to regenerate
      lsRemove(LS_KEY);
    }
  }

  // generate once and cache
  const kp = await genKeys();
  _cachedKeys = kp;

  // best-effort store JWK to localStorage
  try {
    const enc_pub  = await exportPublicJwk(kp.enc.publicKey);
    const enc_priv = await exportPrivateJwk(kp.enc.privateKey);
    const sig_pub  = await exportPublicJwk(kp.sig.publicKey);
    const sig_priv = await exportPrivateJwk(kp.sig.privateKey);
    lsSet(LS_KEY, JSON.stringify({ enc_pub, enc_priv, sig_pub, sig_priv }));
  } catch {
    // ignore: storage not available, but we still have in-memory cache
  }
  return _cachedKeys;
}

export function clearSavedKeys() {
  _cachedKeys = null;
  lsRemove(LS_KEY);
}

//  utility: SHA-256 fingerprint of the encryption public JWK 
export async function getEncPubFingerprint(keysOrPubJwk) {
  const jwk = keysOrPubJwk.enc?.publicKey
    ? await exportPublicJwk(keysOrPubJwk.enc.publicKey)
    : keysOrPubJwk;
  const enc = new TextEncoder();
  const raw = enc.encode(JSON.stringify(jwk));
  const hash = await subtle.digest('SHA-256', raw);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

//There's something here//
export async function signFrame(frame, privateKey) {
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify({
    type: frame.type,
    from: frame.from,
    to: frame.to,
    ts: frame.ts,
    payload: frame.payload
  }));
  const sig = await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privateKey, data);
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

//There's something here//

// crypto.js  — Replace/update verifyFrame (frontend)
export async function verifyFrame(frame, publicKeyJwk) {
  try {
    // import the RSA-PSS public key (jwk) for verification
    const publicKey = await importSigPub(publicKeyJwk); // importSigPub already implemented
    const enc = new TextEncoder();
    const data = enc.encode(JSON.stringify({
      type: frame.type,
      from: frame.from,
      to: frame.to,
      ts: frame.ts,
      payload: frame.payload
    }));
    // frame.sig is generated on the client side using btoa -> base64 encoding
    const sigRaw = atob(frame.sig);
    const sigBuf = new Uint8Array(sigRaw.split('').map(c => c.charCodeAt(0)));
    // Use RSA-PSS SHA256 / salt length 32 for verification
    return await subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, publicKey, sigBuf, data);
  } catch (e) {
    // console.debug && console.debug('verifyFrame failed', e);
    return false;
  }
}

