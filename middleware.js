import { next } from '@vercel/functions';
import { verifyToken, parseCookie } from './lib/auth.js';

// Routing Middleware не входит в лимит "12 функций" на Hobby-плане Vercel —
// это отдельный механизм, выполняется на edge перед отдачей любой страницы.
export const config = {
  // Срабатывает на всё, КРОМЕ:
  //  - /api/login      (иначе форма логина не сможет отправить пароль)
  //  - /api/logout      (чтобы можно было выйти)
  //  - login.html       (сама страница логина)
  //  - favicon.ico
  matcher: ['/((?!api/login|api/logout|login\\.html|favicon\\.ico).*)'],
};

export default async function middleware(request) {
  const AUTH_SECRET = process.env.AUTH_SECRET;

  if (!AUTH_SECRET) {
    return new Response(
      'Сервер не настроен: в переменных окружения Vercel отсутствует AUTH_SECRET.',
      { status: 500 },
    );
  }

  const token = parseCookie(request, 'auth');
  const isValid = await verifyToken(token, AUTH_SECRET);

  if (!isValid) {
    const loginUrl = new URL('/login.html', request.url);
    return Response.redirect(loginUrl, 302);
  }

  // Кука валидна — пропускаем запрос дальше, к статике (index.html и т.д.)
  return next();
}
