import { NextRequest, NextResponse } from 'next/server';
import { assertPublicUrl, sanitizeAuthHeader, sanitizeCustomHeaders, sanitizeHeaderValue } from '@/lib/ssrf-guard';

/**
 * Send a task to an A2A agent via JSON-RPC tasks/send method
 */
export async function POST(request: NextRequest) {
  try {
    const { agentUrl, authType, authValue, authHeader, customHeaders, message } = await request.json();

    if (!agentUrl || !message) {
      return NextResponse.json({ error: 'Agent URL and message required' }, { status: 400 });
    }

    try {
      assertPublicUrl(agentUrl);
    } catch (err) {
      return NextResponse.json(
        { error: err instanceof Error ? err.message : 'Invalid URL' },
        { status: 400 },
      );
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
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

    // Send a task via A2A JSON-RPC
    const taskId = `task-${Date.now()}`;
    const response = await fetch(agentUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tasks/send',
        params: {
          id: taskId,
          message: {
            role: 'user',
            parts: [
              { kind: 'text', text: message },
            ],
          },
        },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return NextResponse.json({
        error: `Agent returned HTTP ${response.status}`,
        details: errorText,
        taskId,
      }, { status: 502 });
    }

    const json = await response.json();
    const result = json?.result || json;

    return NextResponse.json({
      taskId,
      status: result?.status || result,
      artifacts: result?.artifacts || [],
      history: result?.history || [],
      raw: json,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to send task' },
      { status: 500 }
    );
  }
}
