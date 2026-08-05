// MCP Protocol Types — https://modelcontextprotocol.io/specification/2026-07-28
//
// Revision 2026-07-28 made MCP a stateless request/response protocol: there is
// no initialize handshake and no Mcp-Session-Id, every request carries its
// protocol version and client capabilities in `params._meta`, `server/discover`
// advertises what a server supports, and every result declares a `resultType`.
// The handshake-era ("legacy") types below are kept so the SDK can still talk to
// servers on 2025-11-25 and earlier.

// ─── Published revisions ─────────────────────────────────────────────────────

/** Revisions that use per-request metadata instead of an `initialize` handshake. */
export const MCP_MODERN_VERSIONS = ['2026-07-28'] as const;

/** Revisions that establish a session with an `initialize` handshake. */
export const MCP_LEGACY_VERSIONS = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'] as const;

export const MCP_KNOWN_VERSIONS: string[] = [...MCP_LEGACY_VERSIONS, ...MCP_MODERN_VERSIONS];

/** Latest published revision. */
export const MCP_LATEST_VERSION = '2026-07-28';

/** Best handshake-era revision to negotiate when falling back. */
export const MCP_LEGACY_PREFERRED_VERSION = '2025-11-25';

/** Reserved `_meta` keys defined by the specification. */
export const MCP_META_KEYS = {
  protocolVersion: 'io.modelcontextprotocol/protocolVersion',
  clientInfo: 'io.modelcontextprotocol/clientInfo',
  clientCapabilities: 'io.modelcontextprotocol/clientCapabilities',
  serverInfo: 'io.modelcontextprotocol/serverInfo',
  logLevel: 'io.modelcontextprotocol/logLevel',
  subscriptionId: 'io.modelcontextprotocol/subscriptionId',
} as const;

/**
 * Error codes defined by the specification. `-32020`–`-32099` is reserved for
 * the spec; `-32000`–`-32019` is legacy/implementation-defined.
 */
export const MCP_ERROR_CODES = {
  headerMismatch: -32020,
  missingRequiredClientCapability: -32021,
  unsupportedProtocolVersion: -32022,
  /** Pre-2026-07-28 "resource not found"; replaced by `-32602` (Invalid params). */
  legacyResourceNotFound: -32002,
  methodNotFound: -32601,
  invalidParams: -32602,
} as const;

/** Which era of the protocol a server speaks. */
export type MCPEra = 'modern' | 'legacy' | 'unknown';

export interface MCPJsonRPC {
  jsonrpc: '2.0';
  id: string | number | null;
  method: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: MCPError;
}

export interface MCPError {
  code: number;
  message: string;
  data?: unknown;
}

// ─── Stateless protocol (2026-07-28) ─────────────────────────────────────────

/** Per-request metadata a modern request MUST carry. */
export interface MCPRequestMeta {
  'io.modelcontextprotocol/protocolVersion': string;
  'io.modelcontextprotocol/clientCapabilities': MCPClientCapabilities;
  'io.modelcontextprotocol/clientInfo'?: MCPClientInfo;
  'io.modelcontextprotocol/logLevel'?: string;
  [key: string]: unknown;
}

/** `"complete"` for ordinary results, `"input_required"` for MRTR interim results. */
export type MCPResultType = 'complete' | 'input_required' | (string & {});

export interface MCPResultBase {
  /** Required from 2026-07-28; absent on earlier servers, which means "complete". */
  resultType?: MCPResultType;
  _meta?: Record<string, unknown>;
}

/** Caching hints required on list/read results (`CacheableResult`). */
export interface MCPCacheableResult extends MCPResultBase {
  /** Freshness hint in milliseconds; MUST be >= 0. */
  ttlMs?: number;
  /** Whether shared intermediaries may cache the response. */
  cacheScope?: 'public' | 'private';
}

/** Result of `server/discover` — the replacement for the initialize handshake. */
export interface MCPDiscoverResult extends MCPCacheableResult {
  supportedVersions: string[];
  capabilities: MCPServerCapabilities;
  instructions?: string;
}

/** Interim result asking the client for more input (multi round-trip request). */
export interface MCPInputRequiredResult extends MCPResultBase {
  resultType: 'input_required';
  inputRequests: Array<{ method: string; params?: Record<string, unknown>; id?: string | number }>;
  requestState?: unknown;
}

// ─── Handshake era (2025-11-25 and earlier) ──────────────────────────────────

/** @deprecated The initialize handshake was removed in 2026-07-28. */
export interface MCPInitializeRequest {
  protocolVersion: string;
  capabilities: MCPServerCapabilities;
  clientInfo: MCPClientInfo;
}

/** @deprecated The initialize handshake was removed in 2026-07-28. */
export interface MCPInitializeResponse {
  protocolVersion: string;
  capabilities: MCPServerCapabilities;
  serverInfo: MCPServerInfo;
}

export interface MCPServerCapabilities {
  tools?: MCPToolsCapability;
  resources?: MCPResourcesCapability;
  prompts?: MCPPromptsCapability;
  /** @deprecated Deprecated in 2026-07-28; log to stderr or use OpenTelemetry. */
  logging?: MCPLoggingCapability;
  progress?: boolean;
  /** @deprecated Deprecated in 2026-07-28; pass paths as tool parameters instead. */
  roots?: MCPRootsCapability;
  /** @deprecated Deprecated in 2026-07-28; call an LLM provider API directly. */
  sampling?: Record<string, unknown>;
  /** Optional extensions beyond the core protocol, keyed by extension identifier. */
  extensions?: Record<string, Record<string, unknown>>;
}

export interface MCPClientCapabilities {
  /** @deprecated Deprecated in 2026-07-28. */
  roots?: MCPRootsCapability;
  /** @deprecated Deprecated in 2026-07-28. */
  sampling?: Record<string, unknown>;
  elicitation?: Record<string, unknown>;
  extensions?: Record<string, Record<string, unknown>>;
  [key: string]: unknown;
}

export interface MCPToolsCapability {
  listChanged?: boolean;
}

export interface MCPResourcesCapability {
  subscribe?: boolean;
  listChanged?: boolean;
}

export interface MCPPromptsCapability {
  listChanged?: boolean;
}

export interface MCPLoggingCapability {
  level?: string;
}

export interface MCPRootsCapability {
  listChanged?: boolean;
}

export interface MCPClientInfo {
  name: string;
  version: string;
}

export interface MCPServerInfo {
  name: string;
  version: string;
  capabilities?: MCPServerCapabilities;
}

// Tool Types
export interface MCPTool {
  name: string;
  description?: string;
  inputSchema: MCPJSONSchema;
  outputSchema?: MCPJSONSchema;
  annotations?: MCPToolAnnotations;
  _meta?: Record<string, unknown>;
}

export interface MCPToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

/** `tools/list` is a `CacheableResult` from 2026-07-28. */
export interface MCPListToolsResult extends MCPCacheableResult {
  tools: MCPTool[];
  nextCursor?: string;
}

export interface MCPToolCallRequest {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface MCPToolCallResponse {
  content: MCPToolContent[];
  isError?: boolean;
}

export interface MCPToolContent {
  type: 'text' | 'image' | 'resource';
  text?: string;
  mimeType?: string;
  data?: string;
  uri?: string;
}

// Resource Types
export interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface MCPResourceContents {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string;
}

// Prompt Types
export interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: MCPPromptArgument[];
}

export interface MCPPromptArgument {
  name: string;
  description?: string;
  required?: boolean;
  type?: string;
}

export interface MCPPromptMessage {
  role: 'user' | 'assistant';
  content: MCPToolContent;
}

// JSON Schema (simplified). From 2026-07-28 any JSON Schema 2020-12 keyword is
// allowed, and properties may carry an `x-mcp-header` annotation that mirrors
// the value into an `Mcp-Param-{Name}` HTTP header on the Streamable transport.
export interface MCPJSONSchema {
  $schema?: string;
  $ref?: string;
  $defs?: Record<string, MCPJSONSchema>;
  type?: string;
  properties?: Record<string, MCPJSONSchema>;
  items?: MCPJSONSchema | MCPJSONSchema[];
  required?: string[];
  description?: string;
  additionalProperties?: boolean | MCPJSONSchema;
  'x-mcp-header'?: string;
  [key: string]: unknown;
}

// Authentication Types
export interface MCPAuthConfig {
  type: 'none' | 'apiKey' | 'oauth';
  apiKey?: string;
  oauth?: MCPOAuthConfig;
}

export interface MCPOAuthConfig {
  clientId: string;
  clientSecret?: string;
  tokenEndpoint?: string;
  scopes?: string[];
}

// Server Configuration
export interface MCPServerConfig {
  id?: string;
  name: string;
  url: string;
  auth: MCPAuthConfig;
  capabilities?: MCPServerCapabilities;
}

// Compliance Types
export type ComplianceSeverity = 'critical' | 'warning' | 'info';

export interface ComplianceRule {
  id: string;
  name: string;
  description: string;
  severity: ComplianceSeverity;
  /** Eras this rule applies to. Defaults to both when omitted. */
  eras?: MCPEra[];
  check: (server: MCPServerConfig, context: MCPComplianceContext) => ComplianceResult;
}

export interface ComplianceResult {
  passed: boolean;
  ruleId: string;
  message: string;
  severity: ComplianceSeverity;
  details?: Record<string, unknown>;
}

export interface ComplianceReport {
  timestamp: Date;
  serverId: string;
  serverName: string;
  protocolVersion: string;
  /** Which era of the protocol the server was graded against. */
  era: MCPEra;
  /** From `server/discover`, when the server implements it. */
  supportedVersions?: string[];
  results: ComplianceResult[];
  passedCount: number;
  failedCount: number;
  warningCount: number;
}

/** What a compliance rule is handed: the handshake result plus era context. */
export interface MCPComplianceContext {
  era: MCPEra;
  protocolVersion?: string;
  supportedVersions?: string[];
  serverInfo?: MCPServerInfo | null;
  capabilities?: MCPServerCapabilities | null;
  instructions?: string;
  /** `server/discover` result, when available. */
  discover?: MCPDiscoverResult | null;
  /** `initialize` result, when the server is handshake-based. */
  initialize?: MCPInitializeResponse | null;
  /** Whether the server answered `server/discover` at all. */
  discoverImplemented: boolean;
  /** A `tools/list` result, when one was fetched — used for cache-hint rules. */
  toolsResult?: MCPListToolsResult | null;
  /** Whether the server minted an `Mcp-Session-Id` (removed in 2026-07-28). */
  sessionId?: string | null;
}
