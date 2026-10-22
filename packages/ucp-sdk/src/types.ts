// UCP Protocol Types - Based on https://ucp.dev/2026-08-25/specification/overview/
// Spec version: 2026-08-25 (normative schemas: source/schemas/*.json of the
// official Universal-Commerce-Protocol/ucp repository)
//
// The 2026-08-25 profile model differs from 2026-01-23 in structural ways:
//   - services / capabilities / payment_handlers map each name to an ARRAY
//     of entities (one entry per binding), not a single entity.
//   - a service binding carries `transport` as a plain string plus an
//     `endpoint`, instead of a `transport` object with per-protocol keys.
//   - signing keys live in the top-level `keys[]` array (JWK Set), replacing
//     the old `signing_keys` field.
//   - `ucp.supported_versions` maps protocol versions to leaf profile URIs.
// Legacy 2026-01-23 shapes are kept at the bottom of this file, marked
// deprecated, and are normalized into the current model by
// normalizeUCPProfile() in client.ts.

export const UCP_SPEC_VERSION = '2026-08-25';
export const UCP_LEGACY_SPEC_VERSION = '2026-01-23';

export interface UCPClientConfig {
  id?: string;
  name: string;
  baseUrl: string;
  auth?: UCPAuthConfig;
  /**
   * URL of this client's own platform profile. When set, the client sends
   * it in the `UCP-Agent` header (role ucp-agent) so the business can
   * resolve the platform profile and its `keys[]`.
   */
  agentProfileUrl?: string;
  /**
   * Optional RFC 9421 request signer. When set, the client signs business
   * requests with the returned Signature-Input / Signature /
   * Content-Digest headers.
   */
  signer?: UCPRequestSigner;
}

export interface UCPAuthConfig {
  type: 'none' | 'apiKey' | 'oauth';
  apiKey?: string;
  oauth?: UCPOAuthConfig;
}

export interface UCPOAuthConfig {
  clientId: string;
  clientSecret?: string;
  tokenEndpoint?: string;
  scopes?: string[];
}

/** Minimal contract for an RFC 9421 signer plugged into the client. */
export interface UCPRequestSigner {
  sign(input: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  }): Promise<Record<string, string>>;
}

// ============================================================
// UCP Business Profile - served at /.well-known/ucp (2026-08-25)
// ============================================================

/**
 * Top-level UCP profile document.
 *
 * ```json
 * {
 *   "ucp": { "version": "2026-08-25", "services": {…}, "capabilities": {…}, "payment_handlers": {…} },
 *   "keys": [ … ]
 * }
 * ```
 */
export interface UCPBusinessProfile {
  ucp: UCPSpec;
  /** JWK Set of signing keys (replaces `signing_keys` from 2026-01-23) */
  keys?: UCPJWK[];
}

export interface UCPSpec {
  /** Date-based version string in YYYY-MM-DD format (e.g. "2026-08-25") */
  version: string;
  /**
   * Older protocol versions this business supports, mapped to the URI of a
   * complete, self-contained (leaf) profile for that version. When
   * omitted, only `version` is supported.
   */
  supported_versions?: Record<string, string>;
  /** Services keyed by reverse-domain namespace, one array entry per binding */
  services: Record<string, UCPService[]>;
  /** Capabilities keyed by reverse-domain namespace */
  capabilities: Record<string, UCPCapability[]>;
  /** Payment handlers keyed by reverse-domain namespace */
  payment_handlers?: Record<string, UCPPaymentHandler[]>;
}

// ============================================================
// Services (2026-08-25: one array entry per transport binding)
// ============================================================

export type UCPTransport = 'rest' | 'mcp' | 'a2a' | 'embedded';

export interface UCPService {
  /** Service version in YYYY-MM-DD format */
  version: string;
  /** URL pointing to the human-readable specification for this service */
  spec?: string;
  /**
   * URL of the JSON Schema defining this binding. The schema URL is the
   * normative authority for the entity structure.
   */
  schema?: string;
  /** Transport protocol of this binding */
  transport: UCPTransport;
  /** Endpoint URL for this transport binding (required for rest/mcp/a2a) */
  endpoint?: string;
  /** Optional unique identifier */
  id?: string;
  /** Optional configuration object (embedded transport uses this) */
  config?: Record<string, unknown>;
}

// ============================================================
// Capabilities (2026-08-25)
// ============================================================

export interface UCPCapability {
  /** Capability version in YYYY-MM-DD format */
  version: string;
  /** URL pointing to the human-readable specification */
  spec?: string;
  /** JSON Schema URL: the normative authority for this capability */
  schema?: string;
  /** Optional unique identifier */
  id?: string;
  /** Optional configuration object */
  config?: Record<string, unknown>;
  /** For extensions: parent capability name, or list of parent names */
  extends?: string | string[];
}

/** Well-known capability names in the 2026-08-25 spec. */
export const UCP_CAPABILITIES = {
  checkout: 'dev.ucp.shopping.checkout',
  cart: 'dev.ucp.shopping.cart',
  catalogSearch: 'dev.ucp.shopping.catalog.search',
  catalogLookup: 'dev.ucp.shopping.catalog.lookup',
  order: 'dev.ucp.shopping.order',
  identityLinking: 'dev.ucp.common.identity_linking',
} as const;

/** Payment extension capabilities live under this namespace in 2026-08-25. */
export const UCP_PAYMENT_CAPABILITY_NAMESPACE = 'dev.ucp.common.payment.';

// ============================================================
// Payment Handlers (2026-08-25)
// ============================================================

export interface UCPPaymentHandler {
  /** Handler instance identifier (required by the 2026-08-25 schema) */
  id: string;
  /** Handler version in YYYY-MM-DD format */
  version: string;
  /** URL pointing to the human-readable specification */
  spec?: string;
  /** JSON Schema URL defining the handler interface */
  schema?: string;
  /** Instrument types this handler supports; absent means all */
  available_instruments?: UCPAvailableInstrument[];
  /** Optional configuration object */
  config?: Record<string, unknown>;
}

export interface UCPAvailableInstrument {
  type: string;
  [key: string]: unknown;
}

// ============================================================
// Signing Keys (JWK, RFC 7517) - top-level `keys[]` in 2026-08-25
// ============================================================

/**
 * Public JSON Web Key as published in the profile `keys` array.
 * Well-known key types: EC (ES256/ES384) and OKP (EdDSA). The kty, crv and
 * alg vocabularies are open: consumers MUST tolerate values they do not
 * recognize and select keys by `kid`.
 */
export interface UCPJWK {
  /** Key identifier, referenced by Signature-Input keyid (required) */
  kid: string;
  /** Key type, e.g. "EC", "OKP", "RSA" (required) */
  kty: string;
  /** Algorithm, e.g. "ES256", "ES384", "EdDSA" */
  alg?: string;
  /** Public key use, e.g. "sig" */
  use?: string;
  /** Curve: "P-256", "P-384" (EC) or "Ed25519" (OKP) */
  crv?: string;
  /** X coordinate (EC/OKP) or modulus (RSA) */
  x?: string;
  /** Y coordinate (EC) */
  y?: string;
  /** RSA public exponent */
  e?: string;
  /** RSA modulus */
  n?: string;
  [key: string]: unknown;
}

/**
 * @deprecated Renamed to UCPJWK in the 2026-08-25 model. Kept as an alias
 * so existing imports keep compiling.
 */
export type UCPSigningKey = UCPJWK;

// ============================================================
// Identity Linking (dev.ucp.common.identity_linking, OAuth 2.0)
// ============================================================

/**
 * Configuration carried by the `dev.ucp.common.identity_linking`
 * capability: external identity providers and the scopes the business
 * accepts per capability.
 */
export interface UCPIdentityLinkingConfig {
  providers?: Record<string, UCPIdentityProvider[]>;
  scopes?: Record<string, Record<string, unknown>>;
}

export interface UCPIdentityProvider {
  /** Provider mechanism type; identity linking uses "oauth2" */
  type: string;
  /** Base URL of the provider */
  auth_url?: string;
  [key: string]: unknown;
}

/** OAuth 2.0 Authorization Server Metadata (RFC 8414), subset. */
export interface UCPOAuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  scopes_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  [key: string]: unknown;
}

// ============================================================
// Legacy 2026-01-23 shapes (input tolerance only)
// ============================================================

/**
 * Raw profile document as served by a 2026-01-23 business. Profiles of any
 * era are accepted as input and normalized to UCPBusinessProfile.
 */
export interface UCPRawProfile {
  ucp: {
    version: string;
    supported_versions?: Record<string, string>;
    services?: Record<string, UCPService | LegacyUCPService | UCPService[]>;
    capabilities?: Record<string, UCPCapability | UCPCapability[]>;
    payment_handlers?: Record<string, UCPPaymentHandler | UCPPaymentHandler[]>;
    [key: string]: unknown;
  };
  keys?: UCPJWK[];
  /** Legacy key field from 2026-01-23; normalized into `keys` */
  signing_keys?: UCPJWK[];
  [key: string]: unknown;
}

/** @deprecated 2026-01-23 service shape with a per-protocol transport object. */
export interface LegacyUCPService {
  version: string;
  spec: string;
  transport: LegacyUCPTransportBindings;
}

export interface LegacyUCPTransportBindings {
  rest?: LegacyUCPTransportEndpoint;
  mcp?: LegacyUCPTransportEndpoint;
  a2a?: LegacyUCPTransportEndpoint;
  embedded?: LegacyUCPTransportEndpoint;
}

export interface LegacyUCPTransportEndpoint {
  schema?: string;
  endpoint?: string;
}

/**
 * @deprecated The 2026-01-23 transport-object model. In 2026-08-25 a
 * service binding carries `transport` as a string plus `endpoint`.
 */
export type UCPTransportBindings = LegacyUCPTransportBindings;
/** @deprecated See UCPTransportBindings. */
export interface UCPRestTransport extends LegacyUCPTransportEndpoint { schema: string; endpoint: string }
/** @deprecated See UCPTransportBindings. */
export interface UCPMcpTransport extends LegacyUCPTransportEndpoint { schema: string; endpoint: string }
/** @deprecated See UCPTransportBindings. */
export interface UCPA2ATransport extends LegacyUCPTransportEndpoint { endpoint: string }
/** @deprecated See UCPTransportBindings. */
export interface UCPEmbeddedTransport extends LegacyUCPTransportEndpoint { schema: string }

// ============================================================
// Compliance Types
// ============================================================

export type ComplianceSeverity = 'critical' | 'warning' | 'info';

export interface ComplianceRule {
  id: string;
  name: string;
  description: string;
  severity: ComplianceSeverity;
  specRef?: string;
  /**
   * Rules receive the normalized (2026-08-25) profile plus the raw
   * document, so legacy-only findings (e.g. `signing_keys`) stay visible.
   */
  check: (profile: UCPBusinessProfile, raw?: UCPRawProfile) => ComplianceResult;
}

export interface ComplianceResult {
  passed: boolean;
  ruleId: string;
  message: string;
  severity: ComplianceSeverity;
  details?: Record<string, unknown>;
  docUrl?: string;
}

export interface ComplianceReport {
  timestamp: Date;
  baseUrl: string;
  specVersion: string;
  results: ComplianceResult[];
  passedCount: number;
  failedCount: number;
  warningCount: number;
}
