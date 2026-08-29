import { next } from '@vercel/functions';
import {
  createToken,
  createAdminToken,
  verifyToken,
  verifyAdminToken,
  parseCookie,
  loadPasswords,
  findMatchingPassword,
  upsertPassword,
  deletePassword,
  timingSafeEqual,
  getRedis,
  logLogin,
  getLoginLog,
  clearLoginLog,
} from './lib/auth.js';

const COOKIE_MAX_AGE = 60 * 60 * 24 * 7;
const ADMIN_COOKIE_MAX_AGE = 60 * 60 * 8;

export const config = {
  matcher: ['/(.*)'],
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // ---------- 1. LOGIN (обычные пользователи) ----------
  if (pathname === '/api/login') {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
    }

    const AUTH_SECRET = process.env.AUTH_SECRET;
    const passwords = await loadPasswords();

    if (!AUTH_SECRET || passwords.length === 0) {
      return json({ error: 'Сервер не настроен (AUTH_SECRET / пароли).' }, 500);
    }

    let password = '';
    try {
      const body = await request.json();
      password = String(body?.password ?? '');
    } catch {
      return json({ error: 'Некорректный запрос.' }, 400);
    }

    await new Promise((r) => setTimeout(r, 350));

    const match = findMatchingPassword(password, passwords);
    if (!match) {
      return json({ error: 'Неверный пароль.' }, 401);
    }

    // Журнал: имя человека + время
    await logLogin(match.name);

    const token = await createToken(AUTH_SECRET, match.password, COOKIE_MAX_AGE);
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
        'Content-Type': 'application/json',
        'Set-Cookie': cookie,
      },
    });
  }

  // ---------- 2. LOGOUT ----------
  if (pathname === '/api/logout') {
    const cookie = [
      'auth=',
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=Strict',
      'Max-Age=0',
    ].join('; ');

    return new Response(null, {
      status: 302,
      headers: {
        Location: '/login.html',
        'Set-Cookie': cookie,
      },
    });
  }

  // ---------- 3. ADMIN LOGIN ----------
  if (pathname === '/api/admin/login') {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
    }

    const AUTH_SECRET = process.env.AUTH_SECRET;
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

    if (!AUTH_SECRET || !ADMIN_PASSWORD) {
      return json({ error: 'Админка не настроена (AUTH_SECRET / ADMIN_PASSWORD).' }, 500);
    }

    let password = '';
    try {
      const body = await request.json();
      password = String(body?.password ?? '');
    } catch {
      return json({ error: 'Некорректный запрос.' }, 400);
    }

    await new Promise((r) => setTimeout(r, 350));

    if (!timingSafeEqual(password, ADMIN_PASSWORD)) {
      return json({ error: 'Неверный админ-пароль.' }, 401);
    }

    const token = await createAdminToken(AUTH_SECRET, ADMIN_COOKIE_MAX_AGE);
    const cookie = [
      `admin=${token}`,
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=Strict',
      `Max-Age=${ADMIN_COOKIE_MAX_AGE}`,
    ].join('; ');

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': cookie,
      },
    });
  }

  // ---------- 4. ADMIN LOGOUT ----------
  if (pathname === '/api/admin/logout') {
    const cookie = [
      'admin=',
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=Strict',
      'Max-Age=0',
    ].join('; ');

    return new Response(null, {
      status: 302,
      headers: {
        Location: '/admin.html',
        'Set-Cookie': cookie,
      },
    });
  }

  // ---------- 5. ADMIN API ----------
  if (pathname.startsWith('/api/admin/')) {
    const AUTH_SECRET = process.env.AUTH_SECRET;
    if (!AUTH_SECRET) return json({ error: 'Нет AUTH_SECRET' }, 500);

    const adminToken = parseCookie(request, 'admin');
    const isAdmin = await verifyAdminToken(adminToken, AUTH_SECRET);
    if (!isAdmin) return json({ error: 'Нет доступа.' }, 401);

    if (!getRedis()) {
      return json(
        { error: 'Redis не настроен. Добавь UPSTASH_REDIS_REST_URL и UPSTASH_REDIS_REST_TOKEN.' },
        500,
      );
    }

    // GET /api/admin/passwords
    if (pathname === '/api/admin/passwords' && request.method === 'GET') {
      const list = await loadPasswords();
      return json({
        passwords: list.map((e) => ({ name: e.name, password: e.password })),
      });
    }

    // POST /api/admin/passwords
    if (pathname === '/api/admin/passwords' && request.method === 'POST') {
      let name = '';
      let password = '';
      try {
        const body = await request.json();
        name = String(body?.name ?? '').trim();
        password = String(body?.password ?? '');
      } catch {
        return json({ error: 'Некорректный запрос.' }, 400);
      }
      if (!name || !password) return json({ error: 'Укажи имя и пароль.' }, 400);
      if (name.length > 64 || password.length > 128) {
        return json({ error: 'Слишком длинное имя или пароль.' }, 400);
      }
      const list = await upsertPassword(name, password);
      return json({
        ok: true,
        passwords: list.map((e) => ({ name: e.name, password: e.password })),
      });
    }

    // DELETE /api/admin/passwords
    if (pathname === '/api/admin/passwords' && request.method === 'DELETE') {
      let name = '';
      try {
        const body = await request.json();
        name = String(body?.name ?? '').trim();
      } catch {
        return json({ error: 'Некорректный запрос.' }, 400);
      }
      if (!name) return json({ error: 'Укажи имя.' }, 400);
      const list = await deletePassword(name);
      return json({
        ok: true,
        passwords: list.map((e) => ({ name: e.name, password: e.password })),
      });
    }

    // GET /api/admin/log — журнал входов
    if (pathname === '/api/admin/log' && request.method === 'GET') {
      const log = await getLoginLog();
      return json({ log });
    }

    // DELETE /api/admin/log — очистить журнал
    if (pathname === '/api/admin/log' && request.method === 'DELETE') {
      await clearLoginLog();
      return json({ ok: true, log: [] });
    }

    return json({ error: 'Not found' }, 404);
  }

  // ---------- 6. Публичные страницы ----------
  if (
    pathname === '/login.html' ||
    pathname === '/admin.html' ||
    pathname === '/favicon.ico'
  ) {
    return next();
  }

  // ---------- 7. Защита остальных страниц ----------
  const AUTH_SECRET = process.env.AUTH_SECRET;
  const passwords = await loadPasswords();

  if (!AUTH_SECRET) {
    return new Response('Missing AUTH_SECRET', { status: 500 });
  }

  if (passwords.length === 0) {
    return Response.redirect(new URL('/login.html', request.url), 302);
  }

  const token = parseCookie(request, 'auth');
  const isValid = await verifyToken(token, AUTH_SECRET, passwords);

  if (!isValid) {
    return Response.redirect(new URL('/login.html', request.url), 302);
  }

  return next();
}
