import { next } from '@vercel/functions';
import { verifyToken, parseCookie } from './lib/auth.js';

export const config = {
  matcher: ['/(.*)'],
};

export default async function middleware(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // === Жёсткий bypass для публичных путей ===
  if (
    pathname === '/login.html' ||
    pathname === '/api/login' ||
    pathname === '/api/logout' ||
    pathname === '/favicon.ico'
  ) {
    // Добавляем заголовок, чтобы было видно, что новый middleware работает
    return next({
      headers: { 'x-mw': 'public-bypass' },
    });
  }

  const AUTH_SECRET = process.env.AUTH_SECRET;

  if (!AUTH_SECRET) {
    return new Response('Missing AUTH_SECRET', { status: 500 });
  }

  const token = parseCookie(request, 'auth');
  const isValid = await verifyToken(token, AUTH_SECRET);

  if (!isValid) {
    if (pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'x-mw': 'api-blocked',
        },
      });
    }

    return Response.redirect(new URL('/login.html', request.url), 302);
  }

  return next({
    headers: { 'x-mw': 'ok' },
  });
}
