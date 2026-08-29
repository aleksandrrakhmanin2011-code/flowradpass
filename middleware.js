import { next } from '@vercel/functions';
import {
  createToken,
  verifyToken,
  parseCookie,
  loadPasswords,
  findMatchingPassword,
} from './lib/auth.js';

const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 дней

export const config = {
  matcher: ['/(.*)'],
};

export default async function middleware(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // ---------- 1. LOGIN ----------
  if (pathname === '/api/login') {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', {
        status: 405,
        headers: { Allow: 'POST' },
      });
    }

    const AUTH_SECRET = process.env.AUTH_SECRET;
    const passwords = loadPasswords();

    if (!AUTH_SECRET || passwords.length === 0) {
      return Response.json(
        { error: 'Сервер не настроен (AUTH_SECRET / SITE_PASSWORDS_JSON).' },
        { status: 500 },
      );
    }

    let password = '';
    try {
      const body = await request.json();
      password = String(body?.password ?? '');
    } catch {
      return Response.json({ error: 'Некорректный запрос.' }, { status: 400 });
    }

    // Небольшая задержка против брутфорса
    await new Promise((r) => setTimeout(r, 350));

    const match = findMatchingPassword(password, passwords);
    if (!match) {
      return Response.json({ error: 'Неверный пароль.' }, { status: 401 });
    }

    // Токен привязан именно к этому паролю
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

  // ---------- 3. Страница логина и favicon ----------
  if (pathname === '/login.html' || pathname === '/favicon.ico') {
    return next();
  }

  // ---------- 4. Всё остальное — проверка cookie ----------
  const AUTH_SECRET = process.env.AUTH_SECRET;
  const passwords = loadPasswords();

  if (!AUTH_SECRET || passwords.length === 0) {
    return new Response('Missing AUTH_SECRET or SITE_PASSWORDS_JSON', { status: 500 });
  }

  const token = parseCookie(request, 'auth');
  const isValid = await verifyToken(token, AUTH_SECRET, passwords);

  if (!isValid) {
    return Response.redirect(new URL('/login.html', request.url), 302);
  }

  return next();
}
