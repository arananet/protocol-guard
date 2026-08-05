import { NextRequest, NextResponse } from 'next/server';
import {
  buildBaseHeaders,
  cacheHintsOf,
  connectMCP,
  mcpCall,
  resultTypeOf,
} from '@/lib/mcp';

/**
 * List tools from an MCP server.
 *
 * Works against both eras: stateless servers (2026-07-28) are reached via
 * `server/discover` + per-request `_meta`, handshake servers via `initialize`.
 */
export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader, customHeaders } = await request.json();

    if (!serverUrl) {
      return NextResponse.json({ error: 'Server URL required' }, { status: 400 });
    }

    const baseHeaders = buildBaseHeaders({ authType, authValue, authHeader, customHeaders });
    const conn = await connectMCP(serverUrl, baseHeaders);

    if (conn.era === 'unknown') {
      return NextResponse.json(
        { error: conn.error || 'Could not connect to the MCP server' },
        { status: 502 }
      );
    }

    const tools = await mcpCall(conn, serverUrl, baseHeaders, 'tools/list');
    const hints = cacheHintsOf(tools.result);

    return NextResponse.json({
      serverInfo: conn.serverInfo,
      protocolVersion: conn.protocolVersion || null,
      protocolEra: conn.era,
      supportedVersions: conn.supportedVersions || null,
      capabilities: conn.capabilities,
      instructions: conn.instructions || null,
      resultType: resultTypeOf(tools.result) || null,
      cache: hints.hasTtl || hints.hasScope ? { ttlMs: hints.ttlMs, cacheScope: hints.cacheScope } : null,
      tools: tools.result?.tools || [],
      raw: { handshake: conn.raw, tools: tools.raw },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to list tools' },
      { status: 500 }
    );
  }
}
