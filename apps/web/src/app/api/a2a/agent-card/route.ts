import { NextRequest, NextResponse } from 'next/server';

/**
 * Server-side proxy for fetching A2A agent cards.
 * Avoids CORS issues that occur when the browser tries to fetch directly.
 * Stateless — nothing is stored.
 */

export async function POST(request: NextRequest) {
  try {
    const { agentUrl, authType, authValue, authHeader } = await request.json();

    if (!agentUrl) {
      return NextResponse.json({ error: 'Agent URL required' }, { status: 400 });
    }

    const headers: Record<string, string> = {
      'Accept': 'application/json',
    };

    if (authType && authType !== 'none' && authValue) {
      if (authType === 'api_key') {
        headers[authHeader || 'Authorization'] = authValue;
      } else if (authType === 'bearer') {
        headers[authHeader || 'Authorization'] = `Bearer ${authValue}`;
      } else if (authType === 'basic') {
        headers[authHeader || 'Authorization'] = `Basic ${Buffer.from(authValue).toString('base64')}`;
      }
    }

    // Build list of URLs to try (same logic as compliance route)
    const urlsToTry: string[] = [agentUrl];

    if (!agentUrl.endsWith('.json')) {
      const urlObj = new URL(agentUrl);
      const base = urlObj.origin + urlObj.pathname.replace(/\/+$/, '');
      urlsToTry.push(`${base}/.well-known/agent.json`);
      urlsToTry.push(`${urlObj.origin}/.well-known/agent.json`);
    }

    const errors: string[] = [];

    for (const url of [...new Set(urlsToTry)]) {
      try {
        const response = await fetch(url, { headers });

        if (!response.ok) {
          errors.push(`${url} → HTTP ${response.status}`);
          continue;
        }

        const text = await response.text();
        let json;
        try {
          json = JSON.parse(text);
        } catch {
          errors.push(`${url} → Response is not valid JSON`);
          continue;
        }

        // Validate it looks like an agent card
        if (json && (json.name || json.description || json.url || json.skills)) {
          return NextResponse.json({ card: json, resolvedUrl: url });
        }

        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('text/html')) {
          errors.push(`${url} → Returned HTML, not JSON`);
          continue;
        }

        // Got JSON but doesn't look like a typical agent card — return it anyway
        return NextResponse.json({ card: json, resolvedUrl: url });
      } catch (err) {
        errors.push(`${url} → ${err instanceof Error ? err.message : 'fetch failed'}`);
      }
    }

    return NextResponse.json(
      { error: 'Could not fetch agent card from any well-known location', attempts: errors },
      { status: 404 }
    );
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Agent card fetch failed' },
      { status: 500 }
    );
  }
}
