import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  MCP_ERROR_CODES,
  MCP_LATEST_VERSION,
  MCP_META_KEYS,
  buildParamHeaders,
  cacheHintsOf,
  collectXMcpHeaderBindings,
  connectMCP,
  decodeHeaderValue,
  encodeHeaderValue,
  isModernError,
  isModernResult,
  mcpNameFor,
  modernHeaders,
  withRequestMeta,
} from '@/lib/mcp';

// ─── Value encoding (Streamable HTTP) ────────────────────────────────────────

describe('header value encoding', () => {
  it('passes plain ASCII through unchanged', () => {
    expect(encodeHeaderValue('us-west1')).toBe('us-west1');
    expect(encodeHeaderValue('get_weather')).toBe('get_weather');
  });

  it('base64-encodes non-ASCII values', () => {
    expect(encodeHeaderValue('Hello, 世界')).toBe('=?base64?SGVsbG8sIOS4lueVjA==?=');
  });

  it('base64-encodes values with leading/trailing whitespace or newlines', () => {
    expect(encodeHeaderValue(' padded ')).toBe('=?base64?IHBhZGRlZCA=?=');
    expect(encodeHeaderValue('line1\nline2')).toBe('=?base64?bGluZTEKbGluZTI=?=');
  });

  it('encodes plain-ASCII values that look like the sentinel', () => {
    const encoded = encodeHeaderValue('=?base64?literal?=');
    expect(encoded).toBe('=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=');
    expect(decodeHeaderValue(encoded)).toBe('=?base64?literal?=');
  });

  it('round-trips through decode', () => {
    for (const value of ['plain', 'Hello, 世界', ' padded ', 'a\tb']) {
      expect(decodeHeaderValue(encodeHeaderValue(value))).toBe(value);
    }
  });
});

// ─── Mirrored request headers ────────────────────────────────────────────────

describe('standard request headers', () => {
  it('derives Mcp-Name from params.name for tools/call', () => {
    expect(mcpNameFor('tools/call', { name: 'get_weather' })).toBe('get_weather');
  });

  it('derives Mcp-Name from params.uri for resources/read', () => {
    expect(mcpNameFor('resources/read', { uri: 'file:///a.json' })).toBe('file:///a.json');
  });

  it('has no Mcp-Name for methods that carry no name', () => {
    expect(mcpNameFor('tools/list', {})).toBeNull();
  });

  it('mirrors method and version into headers', () => {
    const params = withRequestMeta({ name: 'get_weather' }, MCP_LATEST_VERSION);
    const headers = modernHeaders({}, MCP_LATEST_VERSION, 'tools/call', params);

    expect(headers['MCP-Protocol-Version']).toBe(MCP_LATEST_VERSION);
    expect(headers['Mcp-Method']).toBe('tools/call');
    expect(headers['Mcp-Name']).toBe('get_weather');
  });

  it('omits Mcp-Name on list methods', () => {
    const headers = modernHeaders({}, MCP_LATEST_VERSION, 'tools/list', {});
    expect(headers['Mcp-Name']).toBeUndefined();
  });
});

describe('per-request metadata', () => {
  it('adds the required protocol fields without dropping existing params', () => {
    const params = withRequestMeta({ name: 'x', arguments: { a: 1 } }, MCP_LATEST_VERSION);

    expect(params.name).toBe('x');
    expect(params.arguments).toEqual({ a: 1 });
    expect(params._meta[MCP_META_KEYS.protocolVersion]).toBe(MCP_LATEST_VERSION);
    expect(params._meta[MCP_META_KEYS.clientCapabilities]).toBeDefined();
    expect(params._meta[MCP_META_KEYS.clientInfo]).toBeDefined();
  });

  it('preserves caller-supplied _meta keys', () => {
    const params = withRequestMeta({ _meta: { progressToken: 7 } }, MCP_LATEST_VERSION);
    expect(params._meta.progressToken).toBe(7);
    expect(params._meta[MCP_META_KEYS.protocolVersion]).toBe(MCP_LATEST_VERSION);
  });
});

// ─── x-mcp-header ────────────────────────────────────────────────────────────

describe('x-mcp-header bindings', () => {
  it('accepts a valid annotation on a root property', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        query: { type: 'string' },
      },
    });

    expect(bindings).toHaveLength(1);
    expect(bindings[0].header).toBe('Region');
    expect(bindings[0].path).toEqual(['region']);
    expect(bindings[0].violations).toEqual([]);
  });

  it('accepts nested properties reachable through properties chains', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: {
        filter: {
          type: 'object',
          properties: { tenant: { type: 'string', 'x-mcp-header': 'Tenant' } },
        },
      },
    });

    expect(bindings[0].path).toEqual(['filter', 'tenant']);
    expect(bindings[0].violations).toEqual([]);
  });

  it('rejects annotations that are not statically reachable', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: {
        rows: {
          type: 'array',
          items: {
            type: 'object',
            properties: { region: { type: 'string', 'x-mcp-header': 'Region' } },
          },
        },
      },
    });

    expect(bindings[0].violations.join(' ')).toMatch(/not statically reachable/);
  });

  it('rejects empty, non-token and CRLF-bearing values', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: {
        a: { type: 'string', 'x-mcp-header': '' },
        b: { type: 'string', 'x-mcp-header': 'bad header' },
        c: { type: 'string', 'x-mcp-header': 'X\r\nInjected' },
      },
    });

    expect(bindings).toHaveLength(3);
    for (const binding of bindings) {
      expect(binding.violations.length).toBeGreaterThan(0);
    }
  });

  it('rejects non-primitive and number-typed parameters', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: {
        amount: { type: 'number', 'x-mcp-header': 'Amount' },
        payload: { type: 'object', 'x-mcp-header': 'Payload' },
      },
    });

    expect(bindings[0].violations.join(' ')).toMatch(/may not be mirrored/);
    expect(bindings[1].violations.join(' ')).toMatch(/may not be mirrored/);
  });

  it('rejects case-insensitively duplicated header names', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: {
        a: { type: 'string', 'x-mcp-header': 'Region' },
        b: { type: 'string', 'x-mcp-header': 'region' },
      },
    });

    expect(bindings[0].violations).toEqual([]);
    expect(bindings[1].violations.join(' ')).toMatch(/duplicate/);
  });

  it('builds Mcp-Param headers from arguments, omitting absent values', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: {
        region: { type: 'string', 'x-mcp-header': 'Region' },
        dryRun: { type: 'boolean', 'x-mcp-header': 'DryRun' },
        limit: { type: 'integer', 'x-mcp-header': 'Limit' },
        missing: { type: 'string', 'x-mcp-header': 'Missing' },
      },
    });

    const headers = buildParamHeaders(bindings, { region: 'us-west1', dryRun: false, limit: 42 });

    expect(headers).toEqual({
      'Mcp-Param-Region': 'us-west1',
      'Mcp-Param-DryRun': 'false',
      'Mcp-Param-Limit': '42',
    });
  });

  it('never mirrors a parameter whose annotation is invalid', () => {
    const bindings = collectXMcpHeaderBindings({
      type: 'object',
      properties: { region: { type: 'string', 'x-mcp-header': 'bad header' } },
    });

    expect(buildParamHeaders(bindings, { region: 'us-west1' })).toEqual({});
  });
});

// ─── Cache hints ─────────────────────────────────────────────────────────────

describe('cache hints', () => {
  it('accepts a well-formed CacheableResult', () => {
    const hints = cacheHintsOf({ ttlMs: 300000, cacheScope: 'public' });
    expect(hints.valid).toBe(true);
    expect(hints.ttlMs).toBe(300000);
  });

  it('treats a negative ttl or unknown scope as invalid', () => {
    expect(cacheHintsOf({ ttlMs: -1, cacheScope: 'public' }).valid).toBe(false);
    expect(cacheHintsOf({ ttlMs: 0, cacheScope: 'shared' }).valid).toBe(false);
  });

  it('reports missing hints', () => {
    const hints = cacheHintsOf({ tools: [] });
    expect(hints.hasTtl).toBe(false);
    expect(hints.hasScope).toBe(false);
    expect(hints.valid).toBe(false);
  });
});

// ─── Error / result recognition ──────────────────────────────────────────────

describe('modern envelope recognition', () => {
  it('recognizes spec-defined error codes', () => {
    expect(isModernError({ error: { code: MCP_ERROR_CODES.unsupportedProtocolVersion } })).toBe(true);
    expect(isModernError({ error: { code: MCP_ERROR_CODES.headerMismatch } })).toBe(true);
    expect(isModernError({ error: { code: -32601 } })).toBe(false);
  });

  it('recognizes results by their resultType', () => {
    expect(isModernResult({ result: { resultType: 'complete' } })).toBe(true);
    expect(isModernResult({ result: { tools: [] } })).toBe(false);
  });
});

// ─── Era detection ───────────────────────────────────────────────────────────

function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'content-type': 'application/json', ...(init.headers || {}) },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('connectMCP era detection', () => {
  it('settles on the modern era when server/discover answers', async () => {
    const seen: Array<{ headers: Record<string, string>; body: any }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: any) => {
        seen.push({ headers: init.headers, body: JSON.parse(init.body) });
        return jsonResponse({
          jsonrpc: '2.0',
          id: 1,
          result: {
            resultType: 'complete',
            supportedVersions: [MCP_LATEST_VERSION],
            capabilities: { tools: {} },
            instructions: 'hi',
            ttlMs: 3600000,
            cacheScope: 'public',
            _meta: { [MCP_META_KEYS.serverInfo]: { name: 'demo', version: '1.0.0' } },
          },
        });
      })
    );

    const conn = await connectMCP('https://example.test/mcp', {});

    expect(conn.era).toBe('modern');
    expect(conn.protocolVersion).toBe(MCP_LATEST_VERSION);
    expect(conn.supportedVersions).toEqual([MCP_LATEST_VERSION]);
    expect(conn.serverInfo).toEqual({ name: 'demo', version: '1.0.0' });
    expect(conn.probe.discoverImplemented).toBe(true);
    expect(conn.probe.fellBackToInitialize).toBe(false);

    // The probe must carry the mirrored headers and per-request metadata.
    expect(seen[0].headers['Mcp-Method']).toBe('server/discover');
    expect(seen[0].headers['MCP-Protocol-Version']).toBe(MCP_LATEST_VERSION);
    expect(seen[0].body.params._meta[MCP_META_KEYS.protocolVersion]).toBe(MCP_LATEST_VERSION);
  });

  it('renegotiates after UnsupportedProtocolVersionError', async () => {
    const versions: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: any) => {
        const body = JSON.parse(init.body);
        versions.push(body.params._meta[MCP_META_KEYS.protocolVersion]);

        if (versions.length === 1) {
          return jsonResponse(
            {
              jsonrpc: '2.0',
              id: 1,
              error: {
                code: MCP_ERROR_CODES.unsupportedProtocolVersion,
                message: 'Unsupported protocol version',
                data: { supported: ['2026-07-28'], requested: '2099-01-01' },
              },
            },
            { status: 400 }
          );
        }

        return jsonResponse({
          jsonrpc: '2.0',
          id: 2,
          result: { resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities: {} },
        });
      })
    );

    const conn = await connectMCP('https://example.test/mcp', {});

    expect(conn.probe.unsupportedVersionErrorSeen).toBe(true);
    expect(conn.era).toBe('modern');
    expect(conn.protocolVersion).toBe('2026-07-28');
    expect(versions).toHaveLength(2);
  });

  it('falls back to initialize for a handshake-era server', async () => {
    const methods: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: any) => {
        const body = JSON.parse(init.body);
        methods.push(body.method);

        if (body.method === 'server/discover' || body.method === 'tools/list') {
          return jsonResponse({ error: 'not found' }, { status: 404 });
        }
        if (body.method === 'initialize') {
          return jsonResponse(
            {
              jsonrpc: '2.0',
              id: 1,
              result: {
                protocolVersion: '2025-06-18',
                capabilities: { tools: {}, logging: {} },
                serverInfo: { name: 'old-server', version: '0.9.0' },
              },
            },
            { headers: { 'mcp-session-id': 'sess-123' } }
          );
        }
        return jsonResponse({ jsonrpc: '2.0', id: 9, result: {} });
      })
    );

    const conn = await connectMCP('https://example.test/mcp', {});

    expect(conn.era).toBe('legacy');
    expect(conn.protocolVersion).toBe('2025-06-18');
    expect(conn.serverInfo).toEqual({ name: 'old-server', version: '0.9.0' });
    expect(conn.sessionId).toBe('sess-123');
    expect(conn.probe.fellBackToInitialize).toBe(true);
    expect(methods).toContain('initialize');
    expect(methods).toContain('notifications/initialized');
  });

  it('stays modern when server/discover is missing but real RPCs work', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: any) => {
        const body = JSON.parse(init.body);
        if (body.method === 'server/discover') {
          return jsonResponse(
            { jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'Method not found' } },
            { status: 404 }
          );
        }
        return jsonResponse({
          jsonrpc: '2.0',
          id: 2,
          result: { resultType: 'complete', tools: [], ttlMs: 1000, cacheScope: 'public' },
        });
      })
    );

    const conn = await connectMCP('https://example.test/mcp', {});

    expect(conn.era).toBe('modern');
    expect(conn.probe.discoverImplemented).toBe(false);
    expect(conn.probe.fellBackToInitialize).toBe(false);
  });

  it('reports an unknown era when the server answers nothing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNREFUSED');
      })
    );

    const conn = await connectMCP('https://example.test/mcp', {});

    expect(conn.era).toBe('unknown');
    expect(conn.error).toMatch(/ECONNREFUSED/);
  });
});
