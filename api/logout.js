export default async function handler(request) {
  const cookie = [
    'auth=',
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    'Max-Age=0',
  ].join('; ');

  const loginUrl = new URL('/login.html', request.url);

  return new Response(null, {
    status: 302,
    headers: {
      Location: loginUrl.toString(),
      'set-cookie': cookie,
    },
  });
}
