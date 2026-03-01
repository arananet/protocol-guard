import { NextRequest, NextResponse } from 'next/server';

/**
 * Call a specific tool on an MCP server via JSON-RPC tools/call method
 */
export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader, toolName, arguments: toolArgs } = await request.json();

    if (!serverUrl || !toolName) {
      return NextResponse.json({ error: 'Server URL and tool name required' }, { status: 400 });
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
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
