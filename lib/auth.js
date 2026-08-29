// Общая логика для middleware.js и api/login.js
// Работает через Web Crypto API (globalThis.crypto.subtle),
// поэтому одинаково работает и в Edge-рантайме (middleware),
// и в Node.js-рантайме (api/login.js, там crypto подключается отдельно).

const encoder = new TextEncoder();

function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function getKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

// Создаёт подписанный токен вида "ok.<expires>.<signature>"
// Подделать его без AUTH_SECRET невозможно.
export async function createToken(secret, ttlSeconds = 60 * 60 * 24 * 7) {
  const expires = Date.now() + ttlSeconds * 1000;
  const payload = `ok.${expires}`;
  const key = await getKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return `${payload}.${toBase64Url(sig)}`;
}

// Проверяет токен: формат, срок действия и подпись.
export async function verifyToken(token, secret) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [marker, expiresStr, sigB64] = parts;
  if (marker !== 'ok') return false;

  const expires = Number(expiresStr);
  if (!Number.isFinite(expires) || Date.now() > expires) return false;

  try {
    const key = await getKey(secret);
    const sig = fromBase64Url(sigB64);
    return await crypto.subtle.verify('HMAC', key, sig, encoder.encode(`ok.${expiresStr}`));
  } catch {
    return false;
  }
}

// Сравнение строк без "быстрого выхода" — усложняет тайминг-атаки на пароль.
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export function parseCookie(request, name) {
  const header = request.headers.get('cookie') || '';
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}
