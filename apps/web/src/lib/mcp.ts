/**
 * Shared MCP transport helpers for the API routes.
 *
 * MCP revision `2026-07-28` turned the protocol from a stateful, handshake-based
 * protocol into a stateless request/response one:
 *
 *  - the `initialize` / `notifications/initialized` handshake is gone; every
 *    request carries its protocol version, client identity and client
 *    capabilities in `params._meta`
 *  - `Mcp-Session-Id` is gone from the Streamable HTTP transport
 *  - `server/discover` is a MUST-implement RPC advertising supported versions,
 *    capabilities and identity
 *  - Streamable HTTP POSTs MUST carry `MCP-Protocol-Version`, `Mcp-Method` and
 *    (for `tools/call` / `resources/read` / `prompts/get`) `Mcp-Name` headers
 *  - every result carries `resultType` (`"complete"` or `"input_required"`)
 *  - list/read results carry `ttlMs` + `cacheScope` caching hints
 *
 * Protocol Guard has to talk to both eras, so this module implements the
 * dual-era client described in the spec: probe modern first, inspect the body of
 * a 4xx before falling back, and cache the era for the rest of the scan.
 *
 * Spec: https://modelcontextprotocol.io/specification/2026-07-28
 */

// ─── Published revisions ─────────────────────────────────────────────────────

export * from './mcp-versions';

import {
  MCP_ERROR_CODES,
  MCP_LATEST_VERSION,
  MCP_LEGACY_PREFERRED_VERSION,
  MCP_META_KEYS,
  MCP_MODERN_VERSIONS,
} from './mcp-versions';

/** Methods whose `Mcp-Name` header mirrors a body field. */
const NAMED_METHODS: Record<string, 'name' | 'uri'> = {
  'tools/call': 'name',
  'prompts/get': 'name',
  'resources/read': 'uri',
};

export const CLIENT_INFO = { name: 'protocol-guard', version: '2.0.0' };

/** Capabilities Protocol Guard declares — it consumes servers, it offers nothing back. */
export const CLIENT_CAPABILITIES: Record<string, unknown> = {};

// ─── Types ───────────────────────────────────────────────────────────────────

export type MCPEra = 'modern' | 'legacy' | 'unknown';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export interface MCPCallResult {
  /** Full JSON-RPC envelope as returned by the server. */
  raw: Json;
  /** `raw.result` when present, otherwise the unwrapped body. */
  result: Json;
  error: { code?: number; message?: string; data?: Json } | null;
  status: number;
  headers: Headers | null;
  /** Network/parse failure, if the request never produced a JSON-RPC envelope. */
  transportError?: string;
}

export interface MCPConnection {
  era: MCPEra;
  /** Version actually in use for subsequent requests. */
  protocolVersion?: string;
  /** From `server/discover` (modern) — versions the server says it supports. */
  supportedVersions?: string[];
  serverInfo: { name?: string; version?: string } | null;
  capabilities: Json;
  instructions?: string;
  /** `server/discover` result, when the server implements it. */
  discover: Json;
  /** `initialize` result, when the server is handshake-based. */
  initialize: Json;
  /** Raw envelope of whichever handshake succeeded. */
  raw: Json;
  status: number;
  headers: Headers | null;
  wwwAuthenticate: string | null;
  /**
   * `Mcp-Session-Id` echoed by the server. Removed in 2026-07-28 — a modern
   * server MUST NOT mint or echo one.
   */
  sessionId: string | null;
  /** Human-readable reason the connection failed, if it did. */
  error?: string;
  /** Per-step record of the era probe, surfaced in compliance reports. */
  probe: {
    discoverAttempted: boolean;
    discoverStatus?: number;
    discoverImplemented: boolean;
    discoverErrorCode?: number;
    modernRequestsAccepted: boolean;
    fellBackToInitialize: boolean;
    unsupportedVersionErrorSeen: boolean;
  };
}

// ─── Header helpers ──────────────────────────────────────────────────────────

/**
 * Encodes a header value per the Streamable HTTP "Value Encoding" rules: plain
 * ASCII passes through, anything else (or anything that would be mistaken for
 * the sentinel) is carried as `=?base64?<base64 of UTF-8>?=`.
 */
export function encodeHeaderValue(value: string): string {
  const isSafeAscii = /^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/.test(value) || value === '';
  const looksLikeSentinel = value.startsWith('=?base64?') && value.endsWith('?=');

  if (isSafeAscii && !looksLikeSentinel) return value;
  return `=?base64?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

/** Decodes a possibly base64-sentinel-encoded header value. */
export function decodeHeaderValue(value: string): string {
  if (value.startsWith('=?base64?') && value.endsWith('?=')) {
    const inner = value.slice('=?base64?'.length, -'?='.length);
    try {
      return Buffer.from(inner, 'base64').toString('utf8');
    } catch {
      return value;
    }
  }
  return value;
}

/** The `Mcp-Name` source value for a method, or null when the method has none. */
export function mcpNameFor(method: string, params: Json): string | null {
  const field = NAMED_METHODS[method];
  if (!field) return null;
  const value = params?.[field];
  return typeof value === 'string' ? value : null;
}

// ─── `x-mcp-header` (custom headers from tool parameters) ────────────────────

/** RFC 9110 §5.1 field-name token characters. */
const HTTP_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** Types a mirrored parameter may have — `number` is explicitly not permitted. */
const MIRRORABLE_TYPES = ['string', 'integer', 'boolean'];

export interface XMcpHeaderBinding {
  /** Property path from the schema root, e.g. `["filter", "region"]`. */
  path: string[];
  /** The `{Name}` in `Mcp-Param-{Name}`. */
  header: string;
  type?: string;
  /** Constraint violations — a non-empty list makes the whole tool invalid. */
  violations: string[];
  /** Where the annotation was found, when it is somewhere it may not be. */
  unreachableVia?: string;
}

/**
 * Collects every `x-mcp-header` annotation in a tool's `inputSchema` and checks
 * it against the spec's constraints. Annotations are only valid on properties
 * statically reachable from the root through a chain of `properties` keys;
 * anything found elsewhere (under `items`, `oneOf`, `$ref`, …) invalidates the
 * tool definition, so those are reported too.
 */
export function collectXMcpHeaderBindings(inputSchema: Json): XMcpHeaderBinding[] {
  const bindings: XMcpHeaderBinding[] = [];
  const seen = new Map<string, string[]>();

  const walk = (schema: Json, path: string[], reachable: boolean, via?: string): void => {
    if (!schema || typeof schema !== 'object') return;

    const annotation = schema['x-mcp-header'];
    if (annotation !== undefined && path.length > 0) {
      const violations: string[] = [];
      const header = typeof annotation === 'string' ? annotation : String(annotation);

      if (typeof annotation !== 'string') violations.push('value is not a string');
      if (header === '') violations.push('value is empty');
      if (header !== '' && !HTTP_TOKEN.test(header)) {
        violations.push('value is not a valid HTTP field-name token (RFC 9110 §5.1)');
      }
      if (/[\r\n]/.test(header)) violations.push('value contains CR/LF');

      const type = typeof schema.type === 'string' ? schema.type : undefined;
      if (type && !MIRRORABLE_TYPES.includes(type)) {
        violations.push(`type "${type}" may not be mirrored (only string, integer, boolean)`);
      }
      if (!reachable) {
        violations.push(`annotation is not statically reachable from the schema root (via ${via})`);
      }

      const key = header.toLowerCase();
      const previous = seen.get(key);
      if (previous) {
        violations.push(`duplicate of the annotation on "${previous.join('.')}" (case-insensitive)`);
      } else {
        seen.set(key, path);
      }

      bindings.push({ path, header, type, violations, unreachableVia: reachable ? undefined : via });
    }

    // Reachable continuation: `properties` chains only.
    const properties = schema.properties;
    if (properties && typeof properties === 'object') {
      for (const [name, child] of Object.entries(properties)) {
        walk(child, [...path, name], reachable, via);
      }
    }

    // Everything else can still carry (invalid) annotations worth reporting.
    for (const keyword of ['items', 'oneOf', 'anyOf', 'allOf', 'not', 'if', 'then', 'else', '$defs']) {
      const branch = schema[keyword];
      if (!branch || typeof branch !== 'object') continue;
      const children = Array.isArray(branch) ? branch : [branch];
      for (const child of children) {
        walk(child, path, false, via || keyword);
      }
    }
  };

  walk(inputSchema, [], true);
  return bindings;
}

/** Reads the value at a property path in a tool call's arguments. */
function valueAtPath(args: Json, path: string[]): unknown {
  let cursor: Json = args;
  for (const key of path) {
    if (cursor === null || typeof cursor !== 'object') return undefined;
    cursor = cursor[key];
  }
  return cursor;
}

/**
 * Builds the `Mcp-Param-{Name}` headers a conforming client mirrors from tool
 * arguments. Absent and null values are omitted, per the spec's table.
 */
export function buildParamHeaders(
  bindings: XMcpHeaderBinding[],
  args: Json
): Record<string, string> {
  const headers: Record<string, string> = {};

  for (const binding of bindings) {
    if (binding.violations.length > 0) continue;
    const value = valueAtPath(args, binding.path);
    if (value === undefined || value === null) continue;

    let asString: string;
    if (typeof value === 'string') asString = value;
    else if (typeof value === 'boolean') asString = value ? 'true' : 'false';
    else if (typeof value === 'number' && Number.isInteger(value)) asString = String(value);
    else continue;

    headers[`Mcp-Param-${binding.header}`] = encodeHeaderValue(asString);
  }

  return headers;
}

// ─── Request construction ────────────────────────────────────────────────────

let requestCounter = 0;
function nextId(): number {
  requestCounter += 1;
  return requestCounter;
}

/** Adds the reserved per-request `_meta` fields a modern request MUST carry. */
export function withRequestMeta(params: Json, protocolVersion: string): Json {
  const base = params && typeof params === 'object' ? params : {};
  return {
    ...base,
    _meta: {
      ...(base._meta || {}),
      [MCP_META_KEYS.protocolVersion]: protocolVersion,
      [MCP_META_KEYS.clientInfo]: CLIENT_INFO,
      [MCP_META_KEYS.clientCapabilities]: CLIENT_CAPABILITIES,
    },
  };
}

/** Builds the standard mirrored headers a modern Streamable HTTP POST MUST carry. */
export function modernHeaders(
  baseHeaders: Record<string, string>,
  protocolVersion: string,
  method: string,
  params: Json
): Record<string, string> {
  const headers: Record<string, string> = {
    ...baseHeaders,
    'MCP-Protocol-Version': protocolVersion,
    'Mcp-Method': method,
  };
  const name = mcpNameFor(method, params);
  if (name !== null) headers['Mcp-Name'] = encodeHeaderValue(name);
  return headers;
}

/** Parses a JSON or SSE response body into a JSON-RPC envelope. */
export async function parseMCPResponse(response: Response): Promise<Json> {
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('text/event-stream')) {
    const text = await response.text();
    const dataLine = text.split('\n').find((l) => l.startsWith('data:'));
    if (dataLine) {
      try {
        return JSON.parse(dataLine.replace(/^data:\s*/, ''));
      } catch {
        return { _rawSSE: text };
      }
    }
    return { _rawSSE: text };
  }

  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function postJsonRpc(
  serverUrl: string,
  headers: Record<string, string>,
  body: Json,
  timeoutMs = 15000
): Promise<MCPCallResult> {
  try {
    const response = await fetch(serverUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const raw = await parseMCPResponse(response);
    return {
      raw,
      result: raw?.result !== undefined ? raw.result : raw,
      error: raw?.error || null,
      status: response.status,
      headers: response.headers,
    };
  } catch (err) {
    return {
      raw: null,
      result: null,
      error: null,
      status: 0,
      headers: null,
      transportError: err instanceof Error ? err.message : 'Request failed',
    };
  }
}

/** True when a body is a JSON-RPC error the modern revision defines. */
export function isModernError(raw: Json): boolean {
  const code = raw?.error?.code;
  return (
    code === MCP_ERROR_CODES.headerMismatch ||
    code === MCP_ERROR_CODES.missingRequiredClientCapability ||
    code === MCP_ERROR_CODES.unsupportedProtocolVersion
  );
}

/** True when a result is a well-formed modern (`resultType`-bearing) result. */
export function isModernResult(raw: Json): boolean {
  return typeof raw?.result?.resultType === 'string';
}

// ─── Modern / legacy calls ───────────────────────────────────────────────────

/** Issues a single modern (stateless, per-request `_meta`) JSON-RPC call. */
export async function modernCall(
  serverUrl: string,
  baseHeaders: Record<string, string>,
  protocolVersion: string,
  method: string,
  params: Json = {},
  overrideHeaders?: Record<string, string>
): Promise<MCPCallResult> {
  const withMeta = withRequestMeta(params, protocolVersion);
  const headers =
    overrideHeaders ?? modernHeaders(baseHeaders, protocolVersion, method, withMeta);
  return postJsonRpc(serverUrl, headers, {
    jsonrpc: '2.0',
    id: nextId(),
    method,
    params: withMeta,
  });
}

/** Issues a single legacy (handshake-era) JSON-RPC call. */
export async function legacyCall(
  serverUrl: string,
  headers: Record<string, string>,
  method: string,
  params: Json = {}
): Promise<MCPCallResult> {
  return postJsonRpc(serverUrl, headers, {
    jsonrpc: '2.0',
    id: nextId(),
    method,
    params,
  });
}

/** Issues a call in whichever era the connection settled on. */
export async function mcpCall(
  conn: MCPConnection,
  serverUrl: string,
  baseHeaders: Record<string, string>,
  method: string,
  params: Json = {}
): Promise<MCPCallResult> {
  if (conn.era === 'modern') {
    return modernCall(
      serverUrl,
      baseHeaders,
      conn.protocolVersion || MCP_LATEST_VERSION,
      method,
      params
    );
  }
  const headers = { ...baseHeaders };
  if (conn.protocolVersion) headers['MCP-Protocol-Version'] = conn.protocolVersion;
  if (conn.sessionId) headers['Mcp-Session-Id'] = conn.sessionId;
  return legacyCall(serverUrl, headers, method, params);
}

// ─── Connection ──────────────────────────────────────────────────────────────

function pickModernVersion(supported: unknown): string | null {
  if (!Array.isArray(supported)) return null;
  const usable = supported.filter(
    (v): v is string => typeof v === 'string' && MCP_MODERN_VERSIONS.includes(v)
  );
  return usable.sort().pop() || null;
}

function emptyProbe(): MCPConnection['probe'] {
  return {
    discoverAttempted: false,
    discoverImplemented: false,
    modernRequestsAccepted: false,
    fellBackToInitialize: false,
    unsupportedVersionErrorSeen: false,
  };
}

/**
 * Connects to an MCP server, detecting which era it speaks.
 *
 * Modern first: `server/discover` at the latest revision. A recognized modern
 * JSON-RPC error identifies a modern server (retry at a mutually supported
 * version rather than falling back); anything else means the server is
 * handshake-based and we fall back to `initialize`.
 */
export async function connectMCP(
  serverUrl: string,
  baseHeaders: Record<string, string>
): Promise<MCPConnection> {
  const conn: MCPConnection = {
    era: 'unknown',
    serverInfo: null,
    capabilities: null,
    discover: null,
    initialize: null,
    raw: null,
    status: 0,
    headers: null,
    wwwAuthenticate: null,
    sessionId: null,
    probe: emptyProbe(),
  };

  // ── Step 1: modern probe via `server/discover` ────────────────────────────
  let version = MCP_LATEST_VERSION;
  let discover = await modernCall(serverUrl, baseHeaders, version, 'server/discover');
  conn.probe.discoverAttempted = true;
  conn.probe.discoverStatus = discover.status;
  conn.status = discover.status;
  conn.headers = discover.headers;
  conn.wwwAuthenticate = discover.headers?.get('www-authenticate') || null;
  conn.sessionId = discover.headers?.get('mcp-session-id') || null;

  if (discover.transportError && discover.status === 0) {
    conn.error = discover.transportError;
    return conn;
  }

  // The server rejected our version but told us what it does support.
  if (discover.error?.code === MCP_ERROR_CODES.unsupportedProtocolVersion) {
    conn.probe.unsupportedVersionErrorSeen = true;
    const negotiated = pickModernVersion(discover.error?.data?.supported);
    if (negotiated) {
      version = negotiated;
      discover = await modernCall(serverUrl, baseHeaders, version, 'server/discover');
      conn.probe.discoverStatus = discover.status;
    }
  }

  if (discover.raw?.result !== undefined && !discover.error) {
    conn.era = 'modern';
    conn.protocolVersion = version;
    conn.probe.discoverImplemented = true;
    conn.probe.modernRequestsAccepted = true;
    conn.discover = discover.result;
    conn.raw = discover.raw;
    conn.status = discover.status;
    conn.headers = discover.headers;
    conn.sessionId = discover.headers?.get('mcp-session-id') || null;
    conn.capabilities = discover.result?.capabilities ?? null;
    conn.instructions = discover.result?.instructions;
    conn.supportedVersions = Array.isArray(discover.result?.supportedVersions)
      ? discover.result.supportedVersions
      : undefined;
    conn.serverInfo = discover.result?._meta?.[MCP_META_KEYS.serverInfo] || null;
    return conn;
  }

  conn.probe.discoverErrorCode = discover.error?.code;

  // ── Step 2: modern server that doesn't implement `server/discover` ────────
  // `server/discover` is a MUST, but a server can still be modern without it —
  // probe with a real RPC before concluding the server is handshake-based.
  if (isModernError(discover.raw) || discover.error?.code === MCP_ERROR_CODES.methodNotFound) {
    const probe = await modernCall(serverUrl, baseHeaders, version, 'tools/list');
    if (isModernResult(probe.raw) || (probe.raw?.result !== undefined && !probe.error)) {
      conn.era = 'modern';
      conn.protocolVersion = version;
      conn.probe.modernRequestsAccepted = true;
      conn.raw = probe.raw;
      conn.status = probe.status;
      conn.headers = probe.headers;
      conn.sessionId = probe.headers?.get('mcp-session-id') || null;
      conn.serverInfo = probe.result?._meta?.[MCP_META_KEYS.serverInfo] || null;
      return conn;
    }
    // A recognized modern error on both calls still means a modern server.
    if (isModernError(probe.raw)) {
      conn.era = 'modern';
      conn.protocolVersion = version;
      conn.raw = probe.raw;
      conn.status = probe.status;
      conn.headers = probe.headers;
      conn.error = probe.error?.message || 'Server rejected modern requests';
      return conn;
    }
  }

  // ── Step 3: fall back to the `initialize` handshake ───────────────────────
  conn.probe.fellBackToInitialize = true;
  const legacyHeaders = { ...baseHeaders };
  const init = await legacyCall(serverUrl, legacyHeaders, 'initialize', {
    protocolVersion: MCP_LEGACY_PREFERRED_VERSION,
    capabilities: {},
    clientInfo: CLIENT_INFO,
  });

  conn.status = init.status;
  conn.headers = init.headers;
  conn.wwwAuthenticate = init.headers?.get('www-authenticate') || conn.wwwAuthenticate;
  conn.sessionId = init.headers?.get('mcp-session-id') || null;
  conn.raw = init.raw;

  if (init.transportError || !init.raw || init.error) {
    conn.error =
      init.transportError ||
      init.error?.message ||
      'Server answered neither server/discover nor initialize';
    return conn;
  }

  conn.era = 'legacy';
  conn.initialize = init.result;
  conn.protocolVersion = init.result?.protocolVersion || MCP_LEGACY_PREFERRED_VERSION;
  conn.capabilities = init.result?.capabilities ?? null;
  conn.serverInfo = init.result?.serverInfo || null;
  conn.instructions = init.result?.instructions;

  // Legacy servers expect the initialized notification before any other request.
  const notifyHeaders = { ...legacyHeaders };
  if (conn.protocolVersion) notifyHeaders['MCP-Protocol-Version'] = conn.protocolVersion;
  if (conn.sessionId) notifyHeaders['Mcp-Session-Id'] = conn.sessionId;
  await postJsonRpc(serverUrl, notifyHeaders, {
    jsonrpc: '2.0',
    method: 'notifications/initialized',
    params: {},
  }).catch(() => undefined);

  return conn;
}

// ─── Result shape helpers ────────────────────────────────────────────────────

/** `resultType` is required from 2026-07-28; absent means "complete" on older servers. */
export function resultTypeOf(result: Json): string | undefined {
  return typeof result?.resultType === 'string' ? result.resultType : undefined;
}

export function isInputRequired(result: Json): boolean {
  return resultTypeOf(result) === 'input_required';
}

export interface CacheHints {
  ttlMs?: number;
  cacheScope?: string;
  hasTtl: boolean;
  hasScope: boolean;
  valid: boolean;
}

/** Reads the `CacheableResult` hints a 2026-07-28 list/read result MUST carry. */
export function cacheHintsOf(result: Json): CacheHints {
  const ttlMs = typeof result?.ttlMs === 'number' ? result.ttlMs : undefined;
  const cacheScope = typeof result?.cacheScope === 'string' ? result.cacheScope : undefined;
  return {
    ttlMs,
    cacheScope,
    hasTtl: ttlMs !== undefined,
    hasScope: cacheScope !== undefined,
    valid:
      ttlMs !== undefined &&
      ttlMs >= 0 &&
      (cacheScope === 'public' || cacheScope === 'private'),
  };
}

/** Builds the auth/custom headers shared by every route. */
export function buildBaseHeaders(opts: {
  authType?: string;
  authValue?: string;
  authHeader?: string;
  customHeaders?: Array<{ key?: string; value?: string }>;
}): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  };

  const { authType, authValue, authHeader, customHeaders } = opts;
  if (authType && authType !== 'none' && authValue) {
    if (authType === 'api_key') {
      headers[authHeader || 'Authorization'] = authValue;
    } else if (authType === 'bearer') {
      headers[authHeader || 'Authorization'] = `Bearer ${authValue}`;
    } else if (authType === 'basic') {
      headers[authHeader || 'Authorization'] = `Basic ${Buffer.from(authValue).toString('base64')}`;
    }
  }

  if (Array.isArray(customHeaders)) {
    for (const h of customHeaders) {
      if (h.key && h.value) headers[h.key] = h.value;
    }
  }

  return headers;
}
