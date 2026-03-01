import { NextRequest, NextResponse } from 'next/server';

/**
 * List tools from an MCP server via JSON-RPC tools/list method
 */
export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader } = await request.json();

    if (!serverUrl) {
      return NextResponse.json({ error: 'Server URL required' }, { status: 400 });
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

    // First, initialize the server
    const initResponse = await fetch(serverUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'protocol-guard', version: '1.0.0' },
        },
      }),
    });

    const initJson = await parseResponse(initResponse);
    const initResult = initJson?.result || initJson;

    // Send initialized notification
    try {
      await fetch(serverUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/initialized',
          params: {},
        }),
      });
    } catch {
      // Some servers don't support notifications, that's ok
    }

    // Now list tools
    const toolsResponse = await fetch(serverUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      }),
    });

    const toolsJson = await parseResponse(toolsResponse);
    const toolsResult = toolsJson?.result || toolsJson;

    return NextResponse.json({
      serverInfo: initResult?.serverInfo || null,
      protocolVersion: initResult?.protocolVersion || null,
      capabilities: initResult?.capabilities || null,
      tools: toolsResult?.tools || [],
      raw: { init: initJson, tools: toolsJson },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to list tools' },
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
