import { NextRequest, NextResponse } from 'next/server';
import { assertPublicUrl, sanitizeAuthHeader, sanitizeCustomHeaders, sanitizeHeaderValue } from '@/lib/ssrf-guard';

/**
 * Call a specific tool on an MCP server via JSON-RPC tools/call method
 */
export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader, customHeaders, toolName, arguments: toolArgs } = await request.json();

    if (!serverUrl || !toolName) {
      return NextResponse.json({ error: 'Server URL and tool name required' }, { status: 400 });
    }

    try {
      assertPublicUrl(serverUrl);
    } catch (err) {
      return NextResponse.json(
        { error: err instanceof Error ? err.message : 'Invalid URL' },
        { status: 400 },
      );
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
    };

    const safeAuthHeader = sanitizeAuthHeader(authHeader);
    if (authType && authType !== 'none' && authValue) {
      const safeValue = sanitizeHeaderValue(String(authValue));
      if (authType === 'api_key') {
        headers[safeAuthHeader] = safeValue;
      } else if (authType === 'bearer') {
        headers[safeAuthHeader] = `Bearer ${safeValue}`;
      } else if (authType === 'basic') {
        headers[safeAuthHeader] = `Basic ${Buffer.from(safeValue).toString('base64')}`;
      }
    }

    Object.assign(headers, sanitizeCustomHeaders(customHeaders));

    // Call the tool
    const response = await fetch(serverUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: toolName,
          arguments: toolArgs || {},
        },
      }),
    });

    const json = await parseResponse(response);
    const result = json?.result || json;

    return NextResponse.json({
      toolName,
      result: result?.content || result,
      isError: result?.isError || false,
      raw: json,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to call tool' },
      { status: 500 }
    );
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function parseResponse(response: Response): Promise<any> {
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('text/event-stream')) {
    const text = await response.text();
    const dataLine = text.split('\n').find(l => l.startsWith('data:'));
    if (dataLine) {
      return JSON.parse(dataLine.replace(/^data:\s*/, ''));
    }
    return { _rawSSE: text };
  }

  return response.json();
}
