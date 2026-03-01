import { NextRequest, NextResponse } from 'next/server';

// MCP spec URLs and versions for reference
const MCP_SPEC = {
  version: '2024-11-05',
  urls: {
    base: 'https://modelcontextprotocol.io',
    initialize: 'https://modelcontextprotocol.io/docs/basic-concepts/',
    authentication: 'https://modelcontextprotocol.io/docs/authentication/',
    capabilities: 'https://modelcontextprotocol.io/docs/capabilities/',
  },
};

// MCP compliance rules
const MCP_COMPLIANCE_RULES = [
  { id: 'protocol-version', name: 'Protocol Version', severity: 'critical' },
  { id: 'server-info', name: 'Server Info', severity: 'critical' },
  { id: 'capabilities-object', name: 'Capabilities Object', severity: 'warning' },
  { id: 'tools-capability', name: 'Tools Capability', severity: 'info' },
  { id: 'resources-capability', name: 'Resources Capability', severity: 'info' },
  { id: 'initialize-method', name: 'Initialize Method', severity: 'critical' },
  { id: 'ping-method', name: 'Ping Method', severity: 'info' },
  { id: 'authentication', name: 'Authentication', severity: 'critical' },
];

interface MCPInitializeResponse {
  protocolVersion?: string;
  serverInfo?: {
    name: string;
    version: string;
  };
  capabilities?: {
    tools?: Record<string, unknown>;
    resources?: Record<string, unknown>;
    prompts?: Record<string, unknown>;
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractMCPResult(json: any): { parsed: MCPInitializeResponse | null; raw: any } {
  // MCP servers return JSON-RPC: { jsonrpc: "2.0", id: 1, result: { ... } }
  // We need to extract the result for compliance checks but keep raw for display
  const raw = json;

  if (json?.jsonrpc && json?.result && typeof json.result === 'object') {
    // Standard JSON-RPC response — extract the result payload
    return { parsed: json.result as MCPInitializeResponse, raw };
  }

  if (json?.jsonrpc && json?.error) {
    // JSON-RPC error response
    return { parsed: null, raw };
  }

  // Some servers return the payload directly without JSON-RPC wrapper
  return { parsed: json as MCPInitializeResponse, raw };
}

export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader } = await request.json();

    if (!serverUrl) {
      return NextResponse.json({ error: 'Server URL required' }, { status: 400 });
    }

    // Build headers - MCP servers require accepting both JSON and SSE
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

    const jsonRpcBody = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'protocol-guard', version: '1.0.0' },
      },
    });

    // Attempt to connect to MCP server
    let serverResponse: MCPInitializeResponse | null = null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let rawServerResponse: any = null;
    let authTested = false;
    let authPassed = false;
    let connectionError = '';
    let pingPassed = false;
    let pingMessage = '';

    try {
      const response = await fetch(serverUrl, {
        method: 'POST',
        headers,
        body: jsonRpcBody,
      });

      if (response.status === 401 || response.status === 403) {
        authTested = true;
        authPassed = false;
        rawServerResponse = { _httpStatus: response.status, _statusText: response.statusText };
        // Try to read body anyway for raw display
        try { rawServerResponse._body = await response.json(); } catch { /* ignore */ }
        serverResponse = null;
      } else {
        // Handle SSE responses: if content-type is text/event-stream, parse the first data line
        const contentType = response.headers.get('content-type') || '';
        let json;

        if (contentType.includes('text/event-stream')) {
          const text = await response.text();
          // SSE format: lines like "data: {...}\n\n"
          const dataLine = text.split('\n').find(l => l.startsWith('data:'));
          if (dataLine) {
            json = JSON.parse(dataLine.replace(/^data:\s*/, ''));
          } else {
            json = { _rawSSE: text };
          }
        } else {
          json = await response.json();
        }

        const { parsed, raw } = extractMCPResult(json);
        serverResponse = parsed;
        rawServerResponse = raw;

        if (authType && authType !== 'none') {
          authTested = true;
          authPassed = !!serverResponse?.serverInfo;
        }
      }
    } catch (err: unknown) {
      const error = err as Error & { cause?: { code?: string } };
      connectionError = error.message || 'Connection failed';

      // Try without auth as fallback
      try {
        const fallbackResponse = await fetch(serverUrl, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
          },
          body: jsonRpcBody,
        });

        const contentType = fallbackResponse.headers.get('content-type') || '';
        let json;

        if (contentType.includes('text/event-stream')) {
          const text = await fallbackResponse.text();
          const dataLine = text.split('\n').find(l => l.startsWith('data:'));
          json = dataLine ? JSON.parse(dataLine.replace(/^data:\s*/, '')) : { _rawSSE: text };
        } else {
          json = await fallbackResponse.json();
        }

        const { parsed, raw } = extractMCPResult(json);
        serverResponse = parsed;
        rawServerResponse = raw;
      } catch {
        // Both attempts failed — set raw response to show the error
        rawServerResponse = { _error: connectionError, _hint: 'Could not connect to MCP server. Verify the URL and that the server accepts JSON-RPC POST requests.' };
      }
    }

    // Send a real JSON-RPC ping request to verify ping method support
    if (serverResponse) {
      try {
        const pingBody = JSON.stringify({
          jsonrpc: '2.0',
          id: 99,
          method: 'ping',
        });
        const pingResponse = await fetch(serverUrl, {
          method: 'POST',
          headers,
          body: pingBody,
          signal: AbortSignal.timeout(5000),
        });

        const pingContentType = pingResponse.headers.get('content-type') || '';
        let pingJson;

        if (pingContentType.includes('text/event-stream')) {
          const text = await pingResponse.text();
          const dataLine = text.split('\n').find(l => l.startsWith('data:'));
          pingJson = dataLine ? JSON.parse(dataLine.replace(/^data:\s*/, '')) : null;
        } else {
          pingJson = await pingResponse.json();
        }

        // A valid ping response is a JSON-RPC result (can be empty object) with no error
        if (pingJson?.jsonrpc === '2.0' && pingJson?.id === 99 && !pingJson?.error) {
          pingPassed = true;
          pingMessage = 'Server responds to JSON-RPC "ping" method';
        } else if (pingJson?.error) {
          pingPassed = false;
          pingMessage = `Server returned error for ping: ${pingJson.error.message || 'method not found'}`;
        } else {
          pingPassed = false;
          pingMessage = 'Unexpected response format for ping method';
        }
      } catch {
        pingPassed = false;
        pingMessage = 'Ping request failed or timed out (server may not implement ping)';
      }
    }

    // Run compliance checks with specific, actionable messages
    const results = MCP_COMPLIANCE_RULES.map((rule) => {
      let passed = false;
      let message = '';
      let docUrl = '';

      switch (rule.id) {
        case 'protocol-version':
          passed = !!serverResponse?.protocolVersion;
          if (passed) {
            message = `Protocol version present: "${serverResponse?.protocolVersion}"`;
          } else {
            message = `MISSING: Server must return "protocolVersion" in initialize response.`;
            docUrl = MCP_SPEC.urls.initialize;
          }
          break;
        case 'server-info':
          passed = !!(serverResponse?.serverInfo?.name && serverResponse?.serverInfo?.version);
          if (passed) {
            message = `Server info present: "${serverResponse?.serverInfo?.name}" v${serverResponse?.serverInfo?.version}`;
          } else {
            message = `MISSING: Server must return "serverInfo" with "name" and "version".`;
            docUrl = MCP_SPEC.urls.initialize;
          }
          break;
        case 'capabilities-object':
          passed = typeof serverResponse?.capabilities === 'object';
          if (passed) {
            message = `Capabilities object present`;
          } else {
            message = `MISSING: Server must return a "capabilities" object.`;
            docUrl = MCP_SPEC.urls.capabilities;
          }
          break;
        case 'tools-capability':
          passed = true;
          if (serverResponse?.capabilities?.tools) {
            message = `Tools capability declared`;
          } else {
            message = `Tools not declared (optional)`;
            docUrl = MCP_SPEC.urls.capabilities;
          }
          break;
        case 'resources-capability':
          passed = true;
          if (serverResponse?.capabilities?.resources) {
            message = `Resources capability declared`;
          } else {
            message = `Resources not declared (optional)`;
            docUrl = MCP_SPEC.urls.capabilities;
          }
          break;
        case 'initialize-method':
          passed = !!serverResponse?.serverInfo;
          if (passed) {
            message = `Initialize request handled correctly`;
          } else {
            message = `FAILED: Server did not handle the "initialize" JSON-RPC request.`;
            docUrl = MCP_SPEC.urls.initialize;
          }
          break;
        case 'ping-method':
          passed = pingPassed;
          message = pingMessage || 'Ping not tested (initialize failed)';
          if (!passed) {
            docUrl = MCP_SPEC.urls.initialize;
          }
          break;
        case 'authentication':
          if (!authType || authType === 'none') {
            passed = true;
            message = `No authentication configured`;
            docUrl = MCP_SPEC.urls.authentication;
          } else if (authTested) {
            passed = authPassed;
            if (authPassed) {
              message = `Authentication (${authType}) accepted`;
            } else {
              message = `AUTH FAILED: Server returned 401/403.`;
              docUrl = MCP_SPEC.urls.authentication;
            }
          } else {
            passed = true;
            message = `Authentication (${authType}) configured but couldn't verify`;
          }
          break;
      }

      return { passed, ruleId: rule.id, message, severity: rule.severity, docUrl: docUrl || undefined };
    });

    const passedCount = results.filter((r) => r.passed).length;
    const failedCount = results.filter((r) => !r.passed && r.severity === 'critical').length;
    const warningCount = results.filter((r) => !r.passed && r.severity === 'warning').length;

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      protocolVersion: MCP_SPEC.version,
      specUrl: MCP_SPEC.urls.base,
      serverName: serverResponse?.serverInfo?.name || 'Unknown',
      results,
      passedCount,
      failedCount,
      warningCount,
      serverResponse: rawServerResponse || null,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Test failed' },
      { status: 500 }
    );
  }
}
