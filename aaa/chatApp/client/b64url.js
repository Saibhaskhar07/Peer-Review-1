export const toB64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
export const fromB64u = (s) => {
  s = s.replace(/-/g,'+').replace(/_/g,'/'); const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  return Uint8Array.from(atob(s + '='.repeat(pad)), c => c.charCodeAt(0)).buffer;
};
