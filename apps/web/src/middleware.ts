import { NextRequest, NextResponse } from 'next/server';

/**
 * API authentication middleware.
 *
 * When API_SECRET is set in the environment, all /api/* routes (except /api/auth/*)
 * require either:
 *   - A matching X-Api-Key header (for programmatic / curl access), or
 *   - A same-origin request (for the built-in dashboard — the browser sends the
 *     Origin header which must match the Host).
 *
 * When API_SECRET is not set the middleware is a no-op so local development
 * continues to work without configuration.
 */
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (!pathname.startsWith('/api/')) return NextResponse.next();

  // Always allow NextAuth / better-auth internal routes.
  if (pathname.startsWith('/api/auth/')) return NextResponse.next();

  const apiSecret = process.env.API_SECRET;
  // Not configured — open (development mode).
  if (!apiSecret) return NextResponse.next();

  // 1. Programmatic access via API key.
  const apiKey = req.headers.get('x-api-key');
  if (apiKey === apiSecret) return NextResponse.next();

  // 2. Dashboard (same-origin browser request) — Origin must match Host.
  const origin = req.headers.get('origin');
  const host = req.headers.get('host');
  if (origin && host) {
    try {
      const originHost = new URL(origin).host;
      if (originHost === host) return NextResponse.next();
    } catch {
      // Malformed Origin — fall through to 401.
    }
  }

  return NextResponse.json(
    { error: 'Unauthorized. Provide a valid X-Api-Key header.' },
    { status: 401 },
  );
}

export const config = {
  matcher: '/api/:path*',
};
