// UCP Protocol Types - Based on https://ucp.dev/latest/specification/overview/
// Spec version: 2026-01-23

export interface UCPClientConfig {
  id?: string;
  name: string;
  baseUrl: string;
  auth?: UCPAuthConfig;
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

// ============================================================
// UCP Business Profile — served at /.well-known/ucp
// ============================================================

/**
 * Top-level UCP Business Profile.
 *
 * ```json
 * {
 *   "ucp": { "version": "2026-01-23", "services": {…}, "capabilities": {…}, "payment_handlers": {…} },
 *   "signing_keys": [ … ]
 * }
 * ```
 */
export interface UCPBusinessProfile {
  ucp: UCPSpec;
  signing_keys?: UCPSigningKey[];
}

export interface UCPSpec {
  /** Date-based version string in YYYY-MM-DD format (e.g. "2026-01-23") */
  version: string;
  /** Services keyed by reverse-domain namespace, e.g. "dev.ucp.shopping" */
  services: Record<string, UCPService>;
  /** Capabilities keyed by reverse-domain namespace, e.g. "dev.ucp.shopping.checkout" */
  capabilities: Record<string, UCPCapability>;
  /** Payment handlers keyed by reverse-domain namespace, e.g. "com.google.pay" */
  payment_handlers?: Record<string, UCPPaymentHandler>;
}

// ============================================================
// Services
// ============================================================

export interface UCPService {
  /** Service version in YYYY-MM-DD format */
  version: string;
  /** URL pointing to the canonical specification for this service */
  spec: string;
  /** Transport bindings — at least one is required */
  transport: UCPTransportBindings;
}

export interface UCPTransportBindings {
  rest?: UCPRestTransport;
  mcp?: UCPMcpTransport;
  a2a?: UCPA2ATransport;
  embedded?: UCPEmbeddedTransport;
}

export interface UCPRestTransport {
  /** OpenAPI schema URL */
  schema: string;
  /** REST endpoint URL */
  endpoint: string;
}

export interface UCPMcpTransport {
  /** OpenRPC schema URL */
  schema: string;
  /** MCP endpoint URL */
  endpoint: string;
}

export interface UCPA2ATransport {
  /** A2A Agent Card endpoint URL */
  endpoint: string;
}

export interface UCPEmbeddedTransport {
  /** OpenRPC schema URL */
  schema: string;
}

// ============================================================
// Capabilities
// ============================================================

export interface UCPCapability {
  /** Capability version in YYYY-MM-DD format */
  version: string;
  /** URL pointing to the canonical specification */
  spec: string;
  /** JSON Schema URL defining request/response shapes */
  schema: string;
  /** Optional unique identifier */
  id?: string;
  /** Optional configuration object */
  config?: Record<string, unknown>;
  /** For extensions: reverse-domain name of parent capability being extended */
  extends?: string;
}

// ============================================================
// Payment Handlers
// ============================================================

export interface UCPPaymentHandler {
  /** Handler version in YYYY-MM-DD format */
  version: string;
  /** URL pointing to the canonical specification */
  spec: string;
  /** JSON Schema URL defining the handler interface */
  schema: string;
}

// ============================================================
// Signing Keys  (JWK format for webhook verification)
// ============================================================

export interface UCPSigningKey {
  /** Key type, e.g. "EC", "RSA" */
  kty: string;
  /** Key ID */
  kid?: string;
  /** Algorithm, e.g. "ES256" */
  alg?: string;
  /** Public key use, e.g. "sig" */
  use?: string;
  /** Curve for EC keys, e.g. "P-256" */
  crv?: string;
  /** X coordinate (EC) or modulus (RSA) */
  x?: string;
  /** Y coordinate (EC) */
  y?: string;
  /** RSA public exponent */
  e?: string;
  /** RSA modulus */
  n?: string;
}

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
  check: (profile: UCPBusinessProfile) => ComplianceResult;
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
