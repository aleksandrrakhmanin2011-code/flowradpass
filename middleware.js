import { next } from '@vercel/functions';
import { verifyToken, parseCookie } from './lib/auth.js';

// Пути, которые middleware НЕ должен трогать
const PUBLIC = new Set([
  '/login.html',
  '/api/login',
  '/api/logout',
  '/favicon.ico',
]);

export const config = {
  // Берём всё. Исключения делаем внутри функции — так надёжнее.
  matcher: ['/(.*)'],
};

export default async function middleware(request) {
  const { pathname } = new URL(request.url);

  // 1. Публичные пути — сразу пропускаем
  if (PUBLIC.has(pathname)) {
    return next();
  }

  // 2. Секрет
  const AUTH_SECRET = process.env.AUTH_SECRET;
  if (!AUTH_SECRET) {
    return new Response(
      'Сервер не настроен: отсутствует AUTH_SECRET.',
      { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
    );
  }

  // 3. Проверка cookie
  const token = parseCookie(request, 'auth');
  const isValid = await verifyToken(token, AUTH_SECRET);

  if (!isValid) {
    // Для API — 401 (а не редирект)
    if (pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Для страниц — редирект на логин
    return Response.redirect(new URL('/login.html', request.url), 302);
  }

  // Всё ок
  return next();
}
