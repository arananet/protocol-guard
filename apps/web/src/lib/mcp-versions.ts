/**
 * MCP revision constants.
 *
 * Kept free of Node built-ins so client components can import them without
 * pulling the server-side transport helpers (and `Buffer`) into the browser
 * bundle. `@/lib/mcp` re-exports everything here.
 */

/** Revisions that use per-request metadata instead of an `initialize` handshake. */
export const MCP_MODERN_VERSIONS = ['2026-07-28'];

/** Revisions that establish a session with an `initialize` handshake. */
export const MCP_LEGACY_VERSIONS = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'];

export const MCP_KNOWN_VERSIONS = [...MCP_LEGACY_VERSIONS, ...MCP_MODERN_VERSIONS];

/** Latest published revision — what the scanner asks for first. */
export const MCP_LATEST_VERSION = '2026-07-28';

/** Best legacy revision to negotiate when a server turns out to be handshake-based. */
export const MCP_LEGACY_PREFERRED_VERSION = '2025-11-25';

/** Revisions that predate the hardened OAuth Resource Server / Resource Indicator model. */
export const MCP_DEPRECATED_VERSIONS: Record<string, string> = {
  '2024-11-05': 'No standardized authorization framework — predates OAuth 2.1 support entirely.',
  '2025-03-26':
    'OAuth 2.1 present but predates Resource Indicators (RFC 8707) and the Protected Resource Metadata model, leaving tokens vulnerable to passthrough / confused-deputy attacks.',
};

export const MCP_SPEC_URLS = {
  base: 'https://modelcontextprotocol.io',
  spec: 'https://modelcontextprotocol.io/specification/2026-07-28',
  basic: 'https://modelcontextprotocol.io/specification/2026-07-28/basic',
  versioning: 'https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning',
  discover: 'https://modelcontextprotocol.io/specification/2026-07-28/server/discover',
  transport:
    'https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http',
  caching: 'https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching',
  mrtr: 'https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr',
  authorization: 'https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization',
  clientRegistration:
    'https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration',
  deprecated: 'https://modelcontextprotocol.io/specification/2026-07-28/deprecated',
  changelog: 'https://modelcontextprotocol.io/specification/2026-07-28/changelog',
};

/** Reserved `_meta` keys (2026-07-28 §General fields). */
export const MCP_META_KEYS = {
  protocolVersion: 'io.modelcontextprotocol/protocolVersion',
  clientInfo: 'io.modelcontextprotocol/clientInfo',
  clientCapabilities: 'io.modelcontextprotocol/clientCapabilities',
  serverInfo: 'io.modelcontextprotocol/serverInfo',
  logLevel: 'io.modelcontextprotocol/logLevel',
  subscriptionId: 'io.modelcontextprotocol/subscriptionId',
} as const;

/** Error codes defined by the specification (`-32020`–`-32099` is spec-reserved). */
export const MCP_ERROR_CODES = {
  headerMismatch: -32020,
  missingRequiredClientCapability: -32021,
  unsupportedProtocolVersion: -32022,
  /** Pre-2026-07-28 "resource not found"; replaced by `-32602` (Invalid params). */
  legacyResourceNotFound: -32002,
  methodNotFound: -32601,
  invalidParams: -32602,
} as const;
