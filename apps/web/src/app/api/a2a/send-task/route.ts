import { NextRequest, NextResponse } from 'next/server';

/**
 * Send a task to an A2A agent via JSON-RPC tasks/send method
 */
export async function POST(request: NextRequest) {
  try {
    const { agentUrl, authType, authValue, authHeader, message } = await request.json();

    if (!agentUrl || !message) {
      return NextResponse.json({ error: 'Agent URL and message required' }, { status: 400 });
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
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
