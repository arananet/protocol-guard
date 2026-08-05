import {
  MCP_ERROR_CODES,
  MCP_LATEST_VERSION,
  MCP_LEGACY_PREFERRED_VERSION,
  MCP_META_KEYS,
  MCP_MODERN_VERSIONS,
} from './types.js';
import type {
  MCPServerConfig,
  MCPInitializeResponse,
  MCPDiscoverResult,
  MCPServerCapabilities,
  MCPServerInfo,
  MCPClientCapabilities,
  MCPTool,
  MCPListToolsResult,
  MCPResource,
  MCPPrompt,
  MCPToolCallResponse,
  MCPJsonRPC,
  MCPAuthConfig,
  MCPEra,
  MCPComplianceContext,
} from './types.js';

/** Methods whose `Mcp-Name` header mirrors a body field. */
const NAMED_METHODS: Record<string, 'name' | 'uri'> = {
  'tools/call': 'name',
  'prompts/get': 'name',
  'resources/read': 'uri',
};

/**
 * MCP client that speaks both eras of the protocol.
 *
 * Revision 2026-07-28 removed the `initialize` handshake: every request carries
 * its protocol version, client identity and capabilities in `params._meta`, the
 * Streamable HTTP transport mirrors `Mcp-Method` / `Mcp-Name` into headers, and
 * `server/discover` advertises what the server supports. `connect()` probes that
 * first and falls back to `initialize` only when the server turns out to be
 * handshake-based, then keeps using whichever era it found.
 */
export class MCPClient {
  private url: string;
  private auth: MCPAuthConfig;
  private era: MCPEra = 'unknown';
  private protocolVersion: string | null = null;
  private supportedVersions: string[] | null = null;
  private capabilities: MCPServerCapabilities | null = null;
  private serverInfo: MCPServerInfo | null = null;
  private instructions: string | null = null;
  private discoverResult: MCPDiscoverResult | null = null;
  private initializeResult: MCPInitializeResponse | null = null;
  private discoverImplemented = false;
  private sessionId: string | null = null;
  private accessToken: string | null = null;
  private clientCapabilities: MCPClientCapabilities = {};

  constructor(config: MCPServerConfig) {
    this.url = config.url.replace(/\/$/, '');
    this.auth = config.auth;
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    };

    if (this.auth.type === 'apiKey' && this.auth.apiKey) {
      headers['Authorization'] = `Bearer ${this.auth.apiKey}`;
    } else if (this.auth.type === 'oauth' && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    return headers;
  }

  /**
   * Encodes a header value per the transport's Value Encoding rules: plain ASCII
   * passes through, anything else becomes `=?base64?<base64 of UTF-8>?=`.
   */
  private encodeHeaderValue(value: string): string {
    const isSafeAscii = value === '' || /^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/.test(value);
    const looksLikeSentinel = value.startsWith('=?base64?') && value.endsWith('?=');
    if (isSafeAscii && !looksLikeSentinel) return value;

    const bytes = new TextEncoder().encode(value);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `=?base64?${btoa(binary)}?=`;
  }

  private async post(
    headers: Record<string, string>,
    body: Record<string, unknown>
  ): Promise<{ raw: MCPJsonRPC | null; response: Response }> {
    const response = await fetch(this.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    const contentType = response.headers.get('content-type') || '';
    let raw: MCPJsonRPC | null = null;

    if (contentType.includes('text/event-stream')) {
      const text = await response.text();
      const dataLine = text.split('\n').find((l) => l.startsWith('data:'));
      if (dataLine) {
        try {
          raw = JSON.parse(dataLine.replace(/^data:\s*/, ''));
        } catch {
          raw = null;
        }
      }
    } else {
      try {
        raw = (await response.json()) as MCPJsonRPC;
      } catch {
        raw = null;
      }
    }

    return { raw, response };
  }

  /** Issues a request in whichever era the client connected with. */
  private async request<T>(method: string, params?: Record<string, unknown>): Promise<T> {
    const raw =
      this.era === 'modern'
        ? await this.modernRequest(method, params)
        : await this.legacyRequest(method, params);

    if (raw?.error) {
      throw new Error(`MCP error: ${raw.error.code} - ${raw.error.message}`);
    }
    if (!raw || raw.result === undefined) {
      throw new Error(`MCP request failed: no result for "${method}"`);
    }

    return raw.result as T;
  }

  private async modernRequest(
    method: string,
    params?: Record<string, unknown>,
    versionOverride?: string
  ): Promise<MCPJsonRPC | null> {
    const version = versionOverride || this.protocolVersion || MCP_LATEST_VERSION;
    const withMeta: Record<string, unknown> = {
      ...(params || {}),
      _meta: {
        ...((params?._meta as Record<string, unknown>) || {}),
        [MCP_META_KEYS.protocolVersion]: version,
        [MCP_META_KEYS.clientInfo]: { name: 'protocol-tester', version: '2.0.0' },
        [MCP_META_KEYS.clientCapabilities]: this.clientCapabilities,
      },
    };

    const headers: Record<string, string> = {
      ...this.getHeaders(),
      'MCP-Protocol-Version': version,
      'Mcp-Method': method,
    };

    const nameField = NAMED_METHODS[method];
    if (nameField) {
      const value = withMeta[nameField];
      if (typeof value === 'string') {
        headers['Mcp-Name'] = this.encodeHeaderValue(value);
      }
    }

    const { raw } = await this.post(headers, {
      jsonrpc: '2.0',
      id: this.generateId(),
      method,
      params: withMeta,
    });
    return raw;
  }

  private async legacyRequest(
    method: string,
    params?: Record<string, unknown>
  ): Promise<MCPJsonRPC | null> {
    const headers = this.getHeaders();
    if (this.protocolVersion) headers['MCP-Protocol-Version'] = this.protocolVersion;
    if (this.sessionId) headers['Mcp-Session-Id'] = this.sessionId;

    const { raw } = await this.post(headers, {
      jsonrpc: '2.0',
      id: this.generateId(),
      method,
      params,
    });
    return raw;
  }

  /**
   * Connects to the server, detecting which era it speaks.
   *
   * A recognized modern JSON-RPC error identifies a modern server — the client
   * retries at a mutually supported version rather than falling back. Anything
   * else means the server is handshake-based.
   */
  async connect(): Promise<MCPEra> {
    if (this.auth.type === 'oauth') {
      await this.authenticateOAuth();
    }

    let version = MCP_LATEST_VERSION;
    let discover = await this.modernRequest('server/discover', {}, version);

    if (discover?.error?.code === MCP_ERROR_CODES.unsupportedProtocolVersion) {
      const supported = (discover.error.data as { supported?: unknown })?.supported;
      const negotiated = Array.isArray(supported)
        ? supported
            .filter(
              (v): v is string =>
                typeof v === 'string' && (MCP_MODERN_VERSIONS as readonly string[]).includes(v)
            )
            .sort()
            .pop()
        : undefined;
      if (negotiated) {
        version = negotiated;
        discover = await this.modernRequest('server/discover', {}, version);
      }
    }

    if (discover && discover.result !== undefined && !discover.error) {
      const result = discover.result as MCPDiscoverResult;
      this.era = 'modern';
      this.protocolVersion = version;
      this.discoverImplemented = true;
      this.discoverResult = result;
      this.capabilities = result.capabilities ?? null;
      this.supportedVersions = Array.isArray(result.supportedVersions)
        ? result.supportedVersions
        : null;
      this.instructions = result.instructions ?? null;
      this.serverInfo =
        ((result._meta?.[MCP_META_KEYS.serverInfo] as MCPServerInfo) ?? null) || null;
      return this.era;
    }

    // A modern server may omit `server/discover` even though the spec requires
    // it — probe with a real RPC before concluding the server is legacy.
    if (
      discover?.error?.code === MCP_ERROR_CODES.methodNotFound ||
      discover?.error?.code === MCP_ERROR_CODES.headerMismatch ||
      discover?.error?.code === MCP_ERROR_CODES.missingRequiredClientCapability
    ) {
      const probe = await this.modernRequest('tools/list', {}, version);
      if (probe && probe.result !== undefined && !probe.error) {
        this.era = 'modern';
        this.protocolVersion = version;
        this.serverInfo =
          (((probe.result as MCPListToolsResult)._meta?.[MCP_META_KEYS.serverInfo] as
            | MCPServerInfo
            | undefined) ?? null) || null;
        return this.era;
      }
    }

    // Fall back to the handshake era.
    return this.initialize();
  }

  /**
   * Performs the handshake-era `initialize` exchange.
   *
   * @deprecated The handshake was removed in 2026-07-28 — prefer `connect()`,
   * which uses it only as a fallback.
   */
  async initialize(): Promise<MCPEra> {
    if (this.auth.type === 'oauth' && !this.accessToken) {
      await this.authenticateOAuth();
    }

    const { raw, response } = await this.post(this.getHeaders(), {
      jsonrpc: '2.0',
      id: this.generateId(),
      method: 'initialize',
      params: {
        protocolVersion: MCP_LEGACY_PREFERRED_VERSION,
        capabilities: {},
        clientInfo: { name: 'protocol-tester', version: '2.0.0' },
      },
    });

    if (!raw || raw.error || raw.result === undefined) {
      this.era = 'unknown';
      throw new Error(
        raw?.error
          ? `MCP error: ${raw.error.code} - ${raw.error.message}`
          : 'Server answered neither server/discover nor initialize'
      );
    }

    const result = raw.result as MCPInitializeResponse;
    this.era = 'legacy';
    this.initializeResult = result;
    this.protocolVersion = result.protocolVersion || MCP_LEGACY_PREFERRED_VERSION;
    this.capabilities = result.capabilities ?? null;
    this.serverInfo = result.serverInfo ?? null;
    this.sessionId = response.headers.get('mcp-session-id');

    // Handshake-era servers expect this before any other request.
    const notifyHeaders = this.getHeaders();
    notifyHeaders['MCP-Protocol-Version'] = this.protocolVersion;
    if (this.sessionId) notifyHeaders['Mcp-Session-Id'] = this.sessionId;
    await this.post(notifyHeaders, {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: {},
    }).catch(() => undefined);

    return this.era;
  }

  /** Queries the server's supported versions, capabilities and identity. */
  async discover(): Promise<MCPDiscoverResult> {
    return this.request<MCPDiscoverResult>('server/discover', {});
  }

  private async authenticateOAuth(): Promise<void> {
    if (!this.auth.oauth) return;

    const { oauth } = this.auth;
    const tokenEndpoint = oauth.tokenEndpoint || `${this.url}/oauth/token`;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: oauth.clientId,
        client_secret: oauth.clientSecret || '',
        scope: oauth.scopes?.join(' ') || 'read write',
      }),
    });

    if (!response.ok) {
      throw new Error(`OAuth authentication failed: ${response.status}`);
    }

    const data = (await response.json()) as { access_token: string };
    this.accessToken = data.access_token;
  }

  async listTools(): Promise<MCPTool[]> {
    const result = await this.request<MCPListToolsResult>('tools/list');
    return result.tools;
  }

  /** Like `listTools`, but keeps the result's `resultType` and cache hints. */
  async listToolsResult(): Promise<MCPListToolsResult> {
    return this.request<MCPListToolsResult>('tools/list');
  }

  async callTool(name: string, args?: Record<string, unknown>): Promise<MCPToolCallResponse> {
    return this.request<MCPToolCallResponse>('tools/call', { name, arguments: args });
  }

  async listResources(): Promise<MCPResource[]> {
    const result = await this.request<{ resources: MCPResource[] }>('resources/list');
    return result.resources;
  }

  async readResource(uri: string): Promise<{ contents: Array<{ text?: string; blob?: string }> }> {
    return this.request('resources/read', { uri });
  }

  async listPrompts(): Promise<MCPPrompt[]> {
    const result = await this.request<{ prompts: MCPPrompt[] }>('prompts/list');
    return result.prompts;
  }

  async getPrompt(
    name: string,
    args?: Record<string, unknown>
  ): Promise<{ messages: Array<{ content: { type: string; text: string } }> }> {
    return this.request('prompts/get', { name, arguments: args });
  }

  getEra(): MCPEra {
    return this.era;
  }

  getProtocolVersion(): string | null {
    return this.protocolVersion;
  }

  getSupportedVersions(): string[] | null {
    return this.supportedVersions;
  }

  getCapabilities(): MCPServerCapabilities | null {
    return this.capabilities;
  }

  getServerInfo(): MCPServerInfo | null {
    return this.serverInfo;
  }

  getInstructions(): string | null {
    return this.instructions;
  }

  /** Snapshot of what the compliance rules need to grade this server. */
  getComplianceContext(toolsResult?: MCPListToolsResult | null): MCPComplianceContext {
    return {
      era: this.era,
      protocolVersion: this.protocolVersion ?? undefined,
      supportedVersions: this.supportedVersions ?? undefined,
      serverInfo: this.serverInfo,
      capabilities: this.capabilities,
      instructions: this.instructions ?? undefined,
      discover: this.discoverResult,
      initialize: this.initializeResult,
      discoverImplemented: this.discoverImplemented,
      toolsResult: toolsResult ?? null,
      sessionId: this.sessionId,
    };
  }

  /**
   * `ping` was removed in 2026-07-28 — a stateless server has no handshake to
   * keep alive. Still available against handshake-era servers.
   */
  async ping(): Promise<void> {
    if (this.era === 'modern') {
      throw new Error('ping was removed in MCP 2026-07-28; use server/discover instead');
    }
    await this.request('ping', {});
  }

  async close(): Promise<void> {
    this.era = 'unknown';
    this.protocolVersion = null;
    this.supportedVersions = null;
    this.capabilities = null;
    this.serverInfo = null;
    this.instructions = null;
    this.discoverResult = null;
    this.initializeResult = null;
    this.discoverImplemented = false;
    this.sessionId = null;
    this.accessToken = null;
  }
}

export function createMCPClient(config: MCPServerConfig): MCPClient {
  return new MCPClient(config);
}
