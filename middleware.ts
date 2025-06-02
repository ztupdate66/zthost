import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;

  // Log the request for debugging
  console.log(`Incoming request: ${pathname}${search}`);

  // If the path ends with `.php`, redirect to `/api/secureproxy`
  if (pathname.endsWith('.php')) {
    const url = request.nextUrl.clone();

    // Set the new path to `/api/secureproxy`
    url.pathname = '/api/secureproxy';
    url.search = search; // Preserve query parameters

    // Return a rewrite (internal redirect)
    return NextResponse.rewrite(url);
  }

  // Let all other requests pass through
  return NextResponse.next();
}

// Specify matcher to apply middleware only to .php requests
export const config = {
  matcher: ['/secureproxy.php'],
};
