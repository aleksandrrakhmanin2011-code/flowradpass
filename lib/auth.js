// Общая логика для middleware.js
// Пароли: Redis (админка) → fallback SITE_PASSWORDS_JSON
// Журнал входов в Redis

import { Redis } from '@upstash/redis';

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

export async function hashPassword(password) {
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return toBase64Url(hash).slice(0, 16);
}

export function getRedis() {
  // Поддержка и Upstash, и Vercel KV (KV_REST_API_*)
  const url =
    process.env.UPSTASH_REDIS_REST_URL ||
    process.env.KV_REST_API_URL;
  const token =
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    process.env.KV_REST_API_TOKEN;
  if (!url || !token) return null;
  return new Redis({ url, token });
}

const REDIS_KEY = 'site_passwords';
const LOG_KEY = 'login_log';
const LOG_MAX = 100; // храним последние 100 входов

export async function loadPasswords() {
  const redis = getRedis();
  if (redis) {
    try {
      const data = await redis.get(REDIS_KEY);
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return Object.entries(data).map(([name, password]) => ({
          name: String(name),
          password: String(password),
        }));
      }
      const fromEnv = loadPasswordsFromEnv();
      if (fromEnv.length > 0) {
        const obj = Object.fromEntries(fromEnv.map((e) => [e.name, e.password]));
        await redis.set(REDIS_KEY, obj);
        return fromEnv;
      }
      return [];
    } catch {
      return loadPasswordsFromEnv();
    }
  }
  return loadPasswordsFromEnv();
}

function loadPasswordsFromEnv() {
  const json = process.env.SITE_PASSWORDS_JSON;
  if (!json) return [];
  try {
    const obj = JSON.parse(json);
    return Object.entries(obj).map(([name, password]) => ({
      name: String(name),
      password: String(password),
    }));
  } catch {
    return [];
  }
}

export async function savePasswords(entries) {
  const redis = getRedis();
  if (!redis) throw new Error('Redis не настроен');
  const obj = Object.fromEntries(entries.map((e) => [e.name, e.password]));
  await redis.set(REDIS_KEY, obj);
}

export async function upsertPassword(name, password) {
  const list = await loadPasswords();
  const idx = list.findIndex((e) => e.name === name);
  if (idx >= 0) list[idx].password = password;
  else list.push({ name, password });
  await savePasswords(list);
  return list;
}

export async function deletePassword(name) {
  const list = await loadPasswords();
  const next = list.filter((e) => e.name !== name);
  await savePasswords(next);
  return next;
}

/** Записать вход в журнал */
export async function logLogin(name) {
  const redis = getRedis();
  if (!redis) return;
  try {
    const entry = {
      name: String(name),
      at: new Date().toISOString(),
    };
    // LPUSH + LTRIM — новые сверху, максимум LOG_MAX
    await redis.lpush(LOG_KEY, JSON.stringify(entry));
    await redis.ltrim(LOG_KEY, 0, LOG_MAX - 1);
  } catch {
    // журнал не критичен
  }
}

/** Прочитать журнал (новые сверху) */
export async function getLoginLog() {
  const redis = getRedis();
  if (!redis) return [];
  try {
    const rows = await redis.lrange(LOG_KEY, 0, LOG_MAX - 1);
    return (rows || []).map((row) => {
      if (typeof row === 'object' && row !== null) return row;
      try {
        return JSON.parse(String(row));
      } catch {
        return null;
      }
    }).filter(Boolean);
  } catch {
    return [];
  }
}

/** Очистить журнал */
export async function clearLoginLog() {
  const redis = getRedis();
  if (!redis) return;
  await redis.del(LOG_KEY);
}

export function findMatchingPassword(input, passwords) {
  for (const entry of passwords) {
    if (timingSafeEqual(input, entry.password)) return entry;
  }
  return null;
}

export async function createToken(secret, password, ttlSeconds = 60 * 60 * 24 * 7) {
  const expires = Date.now() + ttlSeconds * 1000;
  const pwHash = await hashPassword(password);
  const payload = `ok.${expires}.${pwHash}`;
  const key = await getKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return `${payload}.${toBase64Url(sig)}`;
}

export async function createAdminToken(secret, ttlSeconds = 60 * 60 * 8) {
  const expires = Date.now() + ttlSeconds * 1000;
  const payload = `admin.${expires}`;
  const key = await getKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return `${payload}.${toBase64Url(sig)}`;
}

export async function verifyAdminToken(token, secret) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [marker, expiresStr, sigB64] = parts;
  if (marker !== 'admin') return false;
  const expires = Number(expiresStr);
  if (!Number.isFinite(expires) || Date.now() > expires) return false;
  try {
    const key = await getKey(secret);
    const sig = fromBase64Url(sigB64);
    const payload = `admin.${expiresStr}`;
    return await crypto.subtle.verify('HMAC', key, sig, encoder.encode(payload));
  } catch {
    return false;
  }
}

export async function verifyToken(token, secret, passwords) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 4) return false;

  const [marker, expiresStr, pwHash, sigB64] = parts;
  if (marker !== 'ok') return false;

  const expires = Number(expiresStr);
  if (!Number.isFinite(expires) || Date.now() > expires) return false;

  let stillValid = false;
  for (const entry of passwords) {
    const h = await hashPassword(entry.password);
    if (h === pwHash) {
      stillValid = true;
      break;
    }
  }
  if (!stillValid) return false;

  try {
    const key = await getKey(secret);
    const sig = fromBase64Url(sigB64);
    const payload = `ok.${expiresStr}.${pwHash}`;
    return await crypto.subtle.verify('HMAC', key, sig, encoder.encode(payload));
  } catch {
    return false;
  }
}

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
