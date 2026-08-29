import { webcrypto } from 'node:crypto';
// На случай, если в рантайме Node.js глобальный crypto недоступен —
// подставляем его вручную, чтобы lib/auth.js работал одинаково везде.
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

import { createToken, timingSafeEqual } from '../lib/auth.js';

const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 дней

export default async function handler(request) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { Allow: 'POST' },
    });
  }

  const SITE_PASSWORD = process.env.SITE_PASSWORD;
  const AUTH_SECRET = process.env.AUTH_SECRET;

  if (!SITE_PASSWORD || !AUTH_SECRET) {
    return json(
      { error: 'Сервер не настроен: заданы не все переменные окружения (SITE_PASSWORD, AUTH_SECRET).' },
      500,
    );
  }

  let password = '';
  try {
    const body = await request.json();
    password = String(body?.password ?? '');
  } catch {
    return json({ error: 'Некорректный запрос.' }, 400);
  }

  // Небольшая искусственная задержка усложняет автоматический перебор пароля.
  await new Promise((resolve) => setTimeout(resolve, 350));

  if (!timingSafeEqual(password, SITE_PASSWORD)) {
    return json({ error: 'Неверный пароль.' }, 401);
  }

  const token = await createToken(AUTH_SECRET, COOKIE_MAX_AGE);
  const cookie = [
    `auth=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    `Max-Age=${COOKIE_MAX_AGE}`,
  ].join('; ');

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'set-cookie': cookie,
    },
  });
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
