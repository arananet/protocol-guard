import { NextRequest, NextResponse } from 'next/server';
import {
  MCP_LATEST_VERSION,
  buildBaseHeaders,
  buildParamHeaders,
  collectXMcpHeaderBindings,
  connectMCP,
  isInputRequired,
  legacyCall,
  modernCall,
  modernHeaders,
  resultTypeOf,
  withRequestMeta,
  type Json,
} from '@/lib/mcp';

/**
 * Call a tool on an MCP server.
 *
 * On the stateless transport a conforming client mirrors `Mcp-Method`,
 * `Mcp-Name` and any `x-mcp-header`-annotated parameters into HTTP headers, so
 * the tool's `inputSchema` is fetched first to find those annotations. Tools
 * with invalid annotations are rejected rather than called, as the spec
 * requires. A server may also answer with a multi round-trip `input_required`
 * result instead of content; that is surfaced rather than treated as output.
 */
export async function POST(request: NextRequest) {
  try {
    const {
      serverUrl,
      authType,
      authValue,
      authHeader,
      customHeaders,
      toolName,
      arguments: toolArgs,
    } = await request.json();

    if (!serverUrl || !toolName) {
      return NextResponse.json({ error: 'Server URL and tool name required' }, { status: 400 });
    }

    const baseHeaders = buildBaseHeaders({ authType, authValue, authHeader, customHeaders });
    const conn = await connectMCP(serverUrl, baseHeaders);

    if (conn.era === 'unknown') {
      return NextResponse.json(
        { error: conn.error || 'Could not connect to the MCP server' },
        { status: 502 }
      );
    }

    const args = toolArgs || {};
    const params = { name: toolName, arguments: args };

    let call;
    let mirroredHeaders: string[] = [];

    if (conn.era === 'modern') {
      const version = conn.protocolVersion || MCP_LATEST_VERSION;
      const schema = await fetchToolSchema(serverUrl, baseHeaders, conn, toolName);
      const bindings = collectXMcpHeaderBindings(schema);
      const invalid = bindings.filter((b) => b.violations.length > 0);

      if (invalid.length > 0) {
        return NextResponse.json(
          {
            error: `Tool "${toolName}" has invalid x-mcp-header annotations and must be rejected by conforming clients.`,
            violations: invalid.map((b) => ({
              property: b.path.join('.'),
              header: b.header,
              reasons: b.violations,
            })),
          },
          { status: 422 }
        );
      }

      const withMeta = withRequestMeta(params, version);
      const paramHeaders = buildParamHeaders(bindings, args);
      mirroredHeaders = Object.keys(paramHeaders);
      const headers = {
        ...modernHeaders(baseHeaders, version, 'tools/call', withMeta),
        ...paramHeaders,
      };
      call = await modernCall(serverUrl, baseHeaders, version, 'tools/call', params, headers);
    } else {
      const headers = { ...baseHeaders };
      if (conn.protocolVersion) headers['MCP-Protocol-Version'] = conn.protocolVersion;
      if (conn.sessionId) headers['Mcp-Session-Id'] = conn.sessionId;
      call = await legacyCall(serverUrl, headers, 'tools/call', params);
    }

    if (call.transportError) {
      return NextResponse.json({ error: call.transportError }, { status: 502 });
    }

    const result = call.result;

    if (isInputRequired(result)) {
      return NextResponse.json({
        toolName,
        protocolEra: conn.era,
        resultType: 'input_required',
        inputRequests: result?.inputRequests || [],
        requestState: result?.requestState ?? null,
        result: null,
        isError: false,
        raw: call.raw,
        note: 'The server needs more input before it can complete this call (multi round-trip request). Answer the inputRequests and retry the original call with inputResponses.',
      });
    }

    return NextResponse.json({
      toolName,
      protocolEra: conn.era,
      resultType: resultTypeOf(result) || null,
      mirroredHeaders,
      result: result?.content || result,
      structuredContent: result?.structuredContent ?? null,
      isError: result?.isError || false,
      raw: call.raw,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to call tool' },
      { status: 500 }
    );
  }
}

/** Fetches the named tool's `inputSchema` so its header annotations can be honoured. */
async function fetchToolSchema(
  serverUrl: string,
  baseHeaders: Record<string, string>,
  conn: { protocolVersion?: string },
  toolName: string
): Promise<Json> {
  const version = conn.protocolVersion || MCP_LATEST_VERSION;
  const listed = await modernCall(serverUrl, baseHeaders, version, 'tools/list');
  const tools: Json[] = listed.result?.tools || [];
  return tools.find((t) => t?.name === toolName)?.inputSchema ?? null;
}
