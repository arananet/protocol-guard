import { NextRequest, NextResponse } from 'next/server';

/**
 * A2A Security Scanner — Agent Card & Endpoint vulnerability analysis
 * 
 * Implements checks inspired by:
 *  - a2a-scanner (https://github.com/cisco-ai-defense/a2a-scanner)
 *  - YARA-like pattern matching
 *  - A2A specification compliance
 *  - Heuristic analysis
 * 
 * All analysis is stateless — nothing is stored.
 */

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
}

interface AgentInterface {
  url?: string;
  // Newer drafts use `protocolBinding`; v0.2.x/v0.3.x use `transport`
  transport?: string;
  protocolBinding?: string;
  protocolVersion?: string;
}

interface AgentExtension {
  uri?: string;
  description?: string;
  required?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  params?: Record<string, any>;
}

interface AgentCardSignature {
  protected?: string;
  signature?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  header?: Record<string, any>;
}

interface AgentCard {
  name?: string;
  description?: string;
  url?: string;
  version?: string;
  protocolVersion?: string;
  iconUrl?: string;
  documentationUrl?: string;
  // Transport selection (A2A v0.2.x+)
  preferredTransport?: string;
  additionalInterfaces?: AgentInterface[];
  supportedInterfaces?: AgentInterface[];
  capabilities?: {
    streaming?: boolean;
    pushNotifications?: boolean;
    stateTransitionHistory?: boolean;
    extensions?: AgentExtension[];
    extendedAgentCard?: boolean;
  };
  supportsAuthenticatedExtendedCard?: boolean;
  // Modern OpenAPI-style security (A2A current spec)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  securitySchemes?: Record<string, any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  security?: Array<Record<string, any>>;
  signatures?: AgentCardSignature[];
  // Legacy (deprecated) authentication block
  authentication?: {
    schemes?: string[];
    credentials?: string;
  };
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  skills?: Array<{
    id?: string;
    name?: string;
    description?: string;
    tags?: string[];
    examples?: string[];
    inputModes?: string[];
    outputModes?: string[];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    security?: Array<Record<string, any>>;
  }>;
  provider?: {
    organization?: string;
    url?: string;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

const A2A_KNOWN_TRANSPORTS = ['JSONRPC', 'GRPC', 'HTTP+JSON'];

// ─── Detection Patterns (YARA-inspired) ──────────────────────────────────────

const INJECTION_PATTERNS = [
  { pattern: /<instructions>/i, name: 'XML injection tag' },
  { pattern: /<system>/i, name: 'System prompt injection' },
  { pattern: /ignore previous/i, name: 'Prompt override attempt' },
  { pattern: /you are now/i, name: 'Role hijacking' },
  { pattern: /do not mention/i, name: 'Suppression directive' },
  { pattern: /never tell the user/i, name: 'Information hiding' },
  { pattern: /override.*instruction/i, name: 'Override directive' },
  { pattern: /forget.*previous/i, name: 'Context reset attempt' },
  { pattern: /act as/i, name: 'Role impersonation (may be benign)' },
];

const SUSPICIOUS_URL_PATTERNS = [
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/, name: 'Non-HTTPS URL', severity: 'high' as Severity },
  { pattern: /\.(ru|cn|tk|ml|ga|cf)\//i, name: 'Suspicious TLD', severity: 'medium' as Severity },
  { pattern: /(?:ngrok|localtunnel|serveo|localhost\.run)/i, name: 'Tunnel service', severity: 'medium' as Severity },
  { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, name: 'IP address instead of domain', severity: 'low' as Severity },
];

const SECRET_PATTERNS = [
  /api[_-]?key\s*[:=]\s*["'][^"']+["']/i,
  /password\s*[:=]\s*["'][^"']+["']/i,
  /secret\s*[:=]\s*["'][^"']+["']/i,
  /bearer\s+[a-zA-Z0-9_.+-]{20,}/i,
  /sk-[a-zA-Z0-9]{20,}/,
  /ghp_[a-zA-Z0-9]{36}/,
];

// ─── Analysis Functions ──────────────────────────────────────────────────────

function analyzeSpecCompliance(card: AgentCard, resolvedUrl: string): Finding[] {
  const findings: Finding[] = [];

  // Required fields per A2A spec
  if (!card.name) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'high',
      title: 'Missing required field: name',
      description: 'The agent card is missing the "name" field, which is required by the A2A specification.',
      recommendation: 'Add a "name" field to the agent card.',
    });
  }

  if (!card.url) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'medium',
      title: 'Missing field: url',
      description: 'The agent card does not specify a URL endpoint.',
      recommendation: 'Add a "url" field pointing to the agent\'s endpoint.',
    });
  }

  if (!card.version) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'low',
      title: 'Missing version field',
      description: 'No version specified in the agent card. This makes it harder to track compatibility.',
      recommendation: 'Add a "version" field (e.g., "1.0.0").',
    });
  }

  if (!card.protocolVersion) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'low',
      title: 'Missing protocolVersion field',
      description: 'The agent card does not declare a "protocolVersion". Current A2A spec revisions require agents to advertise the A2A protocol version they implement so clients can negotiate compatibility.',
      recommendation: 'Add a "protocolVersion" field (e.g., "0.3.0").',
    });
  }

  if (!card.skills || card.skills.length === 0) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'medium',
      title: 'No skills declared',
      description: 'The agent card does not declare any skills. Clients cannot discover agent capabilities.',
      recommendation: 'Add at least one skill to the agent card.',
    });
  }

  if (!card.defaultInputModes || card.defaultInputModes.length === 0) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'low',
      title: 'No input modes declared',
      description: 'The agent card does not specify supported input modes.',
      recommendation: 'Add "defaultInputModes" (e.g., ["text/plain"]).',
    });
  }

  if (!card.defaultOutputModes || card.defaultOutputModes.length === 0) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'low',
      title: 'No output modes declared',
      description: 'The agent card does not specify supported output modes.',
      recommendation: 'Add "defaultOutputModes" (e.g., ["text/plain"]).',
    });
  }

  if (!card.capabilities) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'low',
      title: 'No capabilities declared',
      description: 'The agent card does not declare capabilities (streaming, push notifications, etc.).',
      recommendation: 'Add a "capabilities" object with boolean flags.',
    });
  }

  return findings;
}

function analyzeAuthentication(card: AgentCard, resolvedUrl: string): Finding[] {
  const findings: Finding[] = [];

  const hasModernSecurity =
    (card.securitySchemes && Object.keys(card.securitySchemes).length > 0) ||
    (Array.isArray(card.security) && card.security.length > 0);
  const hasLegacyAuth = !!card.authentication?.schemes?.length;

  if (!hasModernSecurity && !hasLegacyAuth) {
    findings.push({
      category: 'Authentication',
      severity: 'high',
      title: 'No authentication scheme declared',
      description: 'The agent card declares neither "securitySchemes"/"security" (current A2A spec) nor a legacy "authentication" block. The agent endpoint may be publicly accessible without authentication.',
      recommendation: 'Declare OpenAPI-style "securitySchemes" (apiKey, http bearer, oauth2, openIdConnect) and reference them in "security".',
    });
  }

  // Using the deprecated authentication block instead of securitySchemes.
  if (hasLegacyAuth && !hasModernSecurity) {
    findings.push({
      category: 'Spec Compliance',
      severity: 'low',
      title: 'Uses deprecated "authentication" block',
      description: 'The agent card uses the legacy "authentication.schemes" field. Current A2A revisions replace this with OpenAPI-style "securitySchemes" plus a "security" requirements array.',
      evidence: (card.authentication?.schemes || []).join(', '),
      recommendation: 'Migrate to "securitySchemes" and "security".',
    });
  }

  // securitySchemes declared but never referenced by a security requirement.
  if (card.securitySchemes && Object.keys(card.securitySchemes).length > 0 &&
      (!Array.isArray(card.security) || card.security.length === 0)) {
    findings.push({
      category: 'Authentication',
      severity: 'medium',
      title: 'securitySchemes declared but no "security" requirement set',
      description: 'The agent defines securitySchemes but does not list any of them in a top-level "security" requirement. Clients cannot tell which scheme(s) are actually required, and the endpoint may accept unauthenticated calls.',
      recommendation: 'Add a "security" array referencing the required scheme(s).',
    });
  }

  // Inline credentials must never appear in a public card.
  if (card.authentication?.credentials) {
    findings.push({
      category: 'Authentication',
      severity: 'critical',
      title: 'Credentials exposed in agent card',
      description: 'The agent card contains a credentials field. Credentials should never be included in the publicly accessible agent card.',
      evidence: '[REDACTED]',
      recommendation: 'Remove credentials from the agent card immediately.',
    });
  }

  // Inspect securityScheme definitions for weak transport (e.g., apiKey in query string).
  if (card.securitySchemes) {
    for (const [name, scheme] of Object.entries(card.securitySchemes)) {
      if (scheme && typeof scheme === 'object') {
        const s = scheme as { type?: string; in?: string; scheme?: string };
        if (s.type === 'apiKey' && s.in === 'query') {
          findings.push({
            category: 'Authentication',
            severity: 'medium',
            title: `API key passed in query string (scheme "${name}")`,
            description: 'An apiKey security scheme is configured to carry the key in the URL query string. Query strings leak into logs, proxies, and browser history.',
            evidence: `${name}: apiKey in query`,
            recommendation: 'Carry API keys in a header, not a query parameter.',
          });
        }
        if (s.type === 'http' && s.scheme === 'basic') {
          findings.push({
            category: 'Authentication',
            severity: 'low',
            title: `HTTP Basic auth declared (scheme "${name}")`,
            description: 'HTTP Basic transmits reusable base64-encoded credentials on every request. Prefer bearer tokens or OAuth 2.0.',
            evidence: `${name}: http basic`,
            recommendation: 'Use OAuth 2.0 / OpenID Connect or short-lived bearer tokens.',
          });
        }
      }
    }
  }

  return findings;
}

/**
 * A2A Agent Cards MAY be signed with JWS (AgentCardSignature). Clients SHOULD
 * verify signatures when present. An unsigned card cannot be proven authentic,
 * so a man-in-the-middle could tamper with skills, URLs, or security schemes.
 */
function analyzeCardSignature(card: AgentCard): Finding[] {
  const findings: Finding[] = [];

  if (!Array.isArray(card.signatures) || card.signatures.length === 0) {
    findings.push({
      category: 'Integrity',
      severity: 'medium',
      title: 'Agent card is not signed (no JWS signatures)',
      description: 'The agent card carries no "signatures" array. A2A supports JWS-signed agent cards (AgentCardSignature) so clients can verify the card has not been tampered with in transit or at a registry. Without a signature, skills, endpoint URLs, and security schemes can be silently altered.',
      recommendation: 'Sign the agent card with JWS (RFC 7515) using a canonical JSON representation (RFC 8785) and publish the verification key.',
    });
    return findings;
  }

  // Validate each signature has the required JWS structure.
  card.signatures.forEach((sig, i) => {
    if (!sig || !sig.protected || !sig.signature) {
      findings.push({
        category: 'Integrity',
        severity: 'medium',
        title: `Malformed agent card signature [${i}]`,
        description: 'A signature entry is missing the required "protected" header or "signature" value, so it cannot be verified as a valid JWS.',
        recommendation: 'Ensure each signature includes base64url-encoded "protected" and "signature" fields.',
      });
      return;
    }
    // The protected header should declare alg + kid for key discovery.
    try {
      const headerJson = JSON.parse(Buffer.from(sig.protected, 'base64url').toString('utf-8'));
      if (!headerJson.alg || headerJson.alg === 'none') {
        findings.push({
          category: 'Integrity',
          severity: 'high',
          title: `Agent card signature uses no/insecure algorithm [${i}]`,
          description: 'The JWS protected header declares "alg": "none" or omits "alg". An unsecured signature provides no integrity protection.',
          evidence: `alg: ${headerJson.alg || 'missing'}`,
          recommendation: 'Use a strong asymmetric algorithm (e.g., RS256, ES256, EdDSA).',
        });
      }
      if (!headerJson.kid) {
        findings.push({
          category: 'Integrity',
          severity: 'low',
          title: `Agent card signature missing key id (kid) [${i}]`,
          description: 'The JWS protected header omits "kid", making it harder for clients to locate the correct verification key.',
          recommendation: 'Include a "kid" referencing the published JWKS key.',
        });
      }
    } catch {
      findings.push({
        category: 'Integrity',
        severity: 'low',
        title: `Agent card signature has an unparseable protected header [${i}]`,
        description: 'The "protected" header is not valid base64url-encoded JSON.',
        recommendation: 'Encode the protected header as base64url JSON per RFC 7515.',
      });
    }
  });

  return findings;
}

/**
 * Validates declared transports (preferredTransport, additionalInterfaces /
 * supportedInterfaces). A2A recognizes JSONRPC, GRPC and HTTP+JSON; every
 * declared interface endpoint should be served over HTTPS.
 */
function analyzeTransports(card: AgentCard): Finding[] {
  const findings: Finding[] = [];

  const interfaces: AgentInterface[] = [
    ...(Array.isArray(card.additionalInterfaces) ? card.additionalInterfaces : []),
    ...(Array.isArray(card.supportedInterfaces) ? card.supportedInterfaces : []),
  ];

  const allTransports = [
    card.preferredTransport,
    ...interfaces.map(i => i.transport || i.protocolBinding),
  ].filter((t): t is string => !!t);

  for (const t of allTransports) {
    if (!A2A_KNOWN_TRANSPORTS.includes(t)) {
      findings.push({
        category: 'Transport Security',
        severity: 'low',
        title: `Unrecognized transport declared: "${t}"`,
        description: `The agent declares a transport "${t}" that is not one of the A2A-defined bindings (${A2A_KNOWN_TRANSPORTS.join(', ')}). Non-standard transports may not be interoperable or independently security-reviewed.`,
        evidence: t,
        recommendation: 'Use a standard A2A transport binding.',
      });
    }
  }

  for (const iface of interfaces) {
    if (iface.url && iface.url.startsWith('http://') &&
        !iface.url.includes('localhost') && !iface.url.includes('127.0.0.1')) {
      findings.push({
        category: 'Transport Security',
        severity: 'high',
        title: 'Declared interface endpoint uses plaintext HTTP',
        description: `An additional interface (${iface.transport || iface.protocolBinding || 'unknown transport'}) is served over unencrypted HTTP, exposing it to interception and tampering.`,
        evidence: iface.url,
        recommendation: 'Serve all interface endpoints over HTTPS/TLS.',
      });
    }
  }

  return findings;
}

/**
 * Inspects declared protocol extensions (capabilities.extensions), including
 * interactive-UI extensions (A2UI). Server-driven UI rendered from agent
 * responses must be sanitized to prevent injection in the rendering client.
 */
function analyzeExtensions(card: AgentCard): Finding[] {
  const findings: Finding[] = [];
  const extensions = card.capabilities?.extensions;
  if (!Array.isArray(extensions) || extensions.length === 0) return findings;

  for (const ext of extensions) {
    const uri = ext.uri || '';
    const isUi = /a2ui|\bui\b|ag-ui|agent-ui/i.test(uri);

    if (isUi) {
      findings.push({
        category: 'A2A UI Extension',
        severity: 'info',
        title: 'Agent declares an interactive UI extension (A2UI)',
        description: `The agent advertises a UI extension (${uri}). UI payloads are delivered as A2A DataParts (e.g. MIME application/json+a2ui) and rendered by the client. The rendering host MUST treat agent-supplied UI as untrusted: sanitize/escape all content, avoid executing embedded scripts, and require user confirmation for UI-initiated actions.`,
        evidence: uri,
        recommendation: 'Render UI in a sandboxed surface, enforce a strict CSP, and never eval agent-provided markup or handlers.',
      });
    }

    if (ext.required) {
      findings.push({
        category: 'A2A Extensions',
        severity: 'low',
        title: `Required extension declared: ${uri || 'unknown'}`,
        description: 'A required extension means clients that do not implement it cannot interoperate, and they must trust the extension\'s behavior. Verify the extension URI resolves to a reviewed, trusted specification.',
        evidence: uri,
        recommendation: 'Prefer optional extensions; document and pin required extension versions.',
      });
    }
  }

  return findings;
}

/**
 * Checks auxiliary URLs (iconUrl, documentationUrl) for insecure transport and
 * suspicious patterns — these are fetched/rendered by clients and registries.
 */
function analyzeAuxiliaryUrls(card: AgentCard): Finding[] {
  const findings: Finding[] = [];
  const urls: Array<{ field: string; value?: string }> = [
    { field: 'iconUrl', value: card.iconUrl },
    { field: 'documentationUrl', value: card.documentationUrl },
  ];

  for (const { field, value } of urls) {
    if (!value) continue;
    if (value.startsWith('http://') && !value.includes('localhost')) {
      findings.push({
        category: 'Transport Security',
        severity: 'low',
        title: `${field} served over HTTP`,
        description: `The agent card "${field}" points to an unencrypted HTTP URL. Clients and registries fetch this resource; HTTP exposes it to tampering.`,
        evidence: value,
        recommendation: `Serve ${field} over HTTPS.`,
      });
    }
    for (const { pattern, name, severity } of SUSPICIOUS_URL_PATTERNS) {
      if (pattern.test(value)) {
        findings.push({
          category: 'Trust & Provenance',
          severity,
          title: `Suspicious ${field}: ${name}`,
          description: `The "${field}" URL matches a suspicious pattern: ${name}.`,
          evidence: value,
          recommendation: 'Use a verified production URL.',
        });
      }
    }
  }

  return findings;
}

function analyzeEndpointSecurity(resolvedUrl: string): Finding[] {
  const findings: Finding[] = [];

  if (resolvedUrl.startsWith('http://') && !resolvedUrl.includes('localhost') && !resolvedUrl.includes('127.0.0.1')) {
    findings.push({
      category: 'Transport Security',
      severity: 'high',
      title: 'Agent card served over HTTP',
      description: 'The agent card is served over unencrypted HTTP, making it vulnerable to man-in-the-middle attacks.',
      evidence: resolvedUrl,
      recommendation: 'Serve the agent card over HTTPS.',
    });
  }

  for (const { pattern, name, severity } of SUSPICIOUS_URL_PATTERNS) {
    if (pattern.test(resolvedUrl)) {
      findings.push({
        category: 'Endpoint Security',
        severity,
        title: `Suspicious endpoint: ${name}`,
        description: `The agent URL matches a suspicious pattern: ${name}.`,
        evidence: resolvedUrl,
        recommendation: 'Use a production domain with HTTPS.',
      });
    }
  }

  return findings;
}

function analyzeInjectionRisks(card: AgentCard): Finding[] {
  const findings: Finding[] = [];

  // Scan all text fields in the card
  const textFields = [
    { name: 'name', value: card.name },
    { name: 'description', value: card.description },
  ];

  // Add skill descriptions
  if (card.skills) {
    for (const skill of card.skills) {
      textFields.push(
        { name: `skill[${skill.id || skill.name}].name`, value: skill.name },
        { name: `skill[${skill.id || skill.name}].description`, value: skill.description },
      );
      if (skill.examples) {
        for (let i = 0; i < skill.examples.length; i++) {
          textFields.push({
            name: `skill[${skill.id || skill.name}].examples[${i}]`,
            value: skill.examples[i],
          });
        }
      }
    }
  }

  for (const field of textFields) {
    if (!field.value) continue;
    for (const { pattern, name } of INJECTION_PATTERNS) {
      const match = field.value.match(pattern);
      if (match) {
        findings.push({
          category: 'Prompt Injection',
          severity: name.includes('benign') ? 'low' : 'high',
          title: `${name} in ${field.name}`,
          description: `The field "${field.name}" contains a pattern that could be used for prompt injection: "${name}".`,
          evidence: match[0],
          recommendation: 'Review and sanitize agent card text fields.',
        });
      }
    }
  }

  return findings;
}

function analyzeSecretLeakage(card: AgentCard): Finding[] {
  const findings: Finding[] = [];
  const cardJson = JSON.stringify(card);

  for (const pattern of SECRET_PATTERNS) {
    const match = cardJson.match(pattern);
    if (match) {
      findings.push({
        category: 'Secret Leakage',
        severity: 'critical',
        title: 'Potential secret/credential found in agent card',
        description: 'The agent card contains what appears to be an embedded credential or API key.',
        evidence: match[0].substring(0, 10) + '...[REDACTED]',
        recommendation: 'Remove all secrets from the agent card. Use proper secrets management.',
      });
      break;
    }
  }

  return findings;
}

function analyzeProviderInfo(card: AgentCard): Finding[] {
  const findings: Finding[] = [];

  if (!card.provider) {
    findings.push({
      category: 'Trust & Provenance',
      severity: 'medium',
      title: 'No provider information',
      description: 'The agent card does not include provider/organization information, making it harder to verify trust.',
      recommendation: 'Add a "provider" object with organization name and URL.',
    });
  }

  if (card.provider?.url) {
    for (const { pattern, name, severity } of SUSPICIOUS_URL_PATTERNS) {
      if (pattern.test(card.provider.url)) {
        findings.push({
          category: 'Trust & Provenance',
          severity,
          title: `Suspicious provider URL: ${name}`,
          description: `The provider URL matches a suspicious pattern: ${name}.`,
          evidence: card.provider.url,
          recommendation: 'Use a verified, production provider URL.',
        });
      }
    }
  }

  return findings;
}

function analyzeCapabilities(card: AgentCard): Finding[] {
  const findings: Finding[] = [];

  if (card.capabilities?.pushNotifications) {
    findings.push({
      category: 'Attack Surface',
      severity: 'info',
      title: 'Push notifications enabled',
      description: 'This agent supports push notifications. Ensure the notification endpoint validates sender identity.',
      recommendation: 'Implement webhook signature verification for push notifications.',
    });
  }

  if (card.capabilities?.streaming) {
    findings.push({
      category: 'Attack Surface',
      severity: 'info',
      title: 'Streaming enabled',
      description: 'This agent supports streaming responses. Ensure proper SSE validation and content-type enforcement.',
      recommendation: 'Validate SSE streams and implement timeouts.',
    });
  }

  // Check for overly permissive input modes
  if (card.defaultInputModes?.includes('*/*') || card.defaultInputModes?.includes('application/octet-stream')) {
    findings.push({
      category: 'Attack Surface',
      severity: 'medium',
      title: 'Overly permissive input modes',
      description: 'The agent accepts very broad input types, increasing the attack surface.',
      evidence: card.defaultInputModes?.join(', '),
      recommendation: 'Restrict input modes to only the types the agent actually processes.',
    });
  }

  return findings;
}

// ─── Agent Card Fetching ─────────────────────────────────────────────────────

async function fetchAgentCard(url: string, headers: Record<string, string> = {}): Promise<{ card: AgentCard; resolvedUrl: string; legacyPath: boolean }> {
  // Current A2A spec: /.well-known/agent-card.json. Legacy: /.well-known/agent.json
  const attempts = [
    url,
    url.replace(/\/$/, '') + '/.well-known/agent-card.json',
    new URL('/.well-known/agent-card.json', url).toString(),
    url.replace(/\/$/, '') + '/.well-known/agent.json',
    new URL('/.well-known/agent.json', url).toString(),
  ];

  const uniqueAttempts = [...new Set(attempts)];

  for (const attempt of uniqueAttempts) {
    try {
      const res = await fetch(attempt, {
        method: 'GET',
        headers: { 'Accept': 'application/json', ...headers },
      });
      if (res.ok) {
        const data = await res.json();
        if (data && typeof data === 'object' && (data.name || data.skills || data.url)) {
          return { card: data, resolvedUrl: attempt, legacyPath: attempt.includes('/.well-known/agent.json') };
        }
      }
    } catch { /* try next */ }
  }

  throw new Error('Could not fetch agent card from any well-known location');
}

// ─── Security Headers Check ──────────────────────────────────────────────────

async function analyzeSecurityHeaders(url: string, extraHeaders: Record<string, string> = {}): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const res = await fetch(url, { method: 'GET', headers: { 'Accept': 'application/json', ...extraHeaders } });
    const headers = res.headers;

    const securityHeaders: { name: string; severity: Severity; description: string }[] = [
      { name: 'strict-transport-security', severity: 'medium', description: 'HSTS header missing — browser will not enforce HTTPS' },
      { name: 'x-content-type-options', severity: 'low', description: 'X-Content-Type-Options header missing — MIME type sniffing not prevented' },
      { name: 'x-frame-options', severity: 'low', description: 'X-Frame-Options header missing — clickjacking may be possible' },
    ];

    for (const hdr of securityHeaders) {
      if (!headers.get(hdr.name)) {
        findings.push({
          category: 'Security Headers',
          severity: hdr.severity,
          title: `Missing ${hdr.name}`,
          description: hdr.description,
          recommendation: `Add the ${hdr.name} header to the agent card endpoint.`,
        });
      }
    }

    // Check for information leakage
    const serverHeader = headers.get('server');
    if (serverHeader) {
      findings.push({
        category: 'Information Leakage',
        severity: 'low',
        title: 'Server header exposes technology',
        description: `The Server header reveals the technology stack: "${serverHeader}".`,
        evidence: serverHeader,
        recommendation: 'Remove or obscure the Server header.',
      });
    }

    // CORS check
    const corsHeader = headers.get('access-control-allow-origin');
    if (corsHeader === '*') {
      findings.push({
        category: 'CORS',
        severity: 'medium',
        title: 'Wildcard CORS allowed',
        description: 'The endpoint allows any origin via Access-Control-Allow-Origin: *.',
        recommendation: 'Restrict CORS to specific trusted origins.',
      });
    }
  } catch {
    // Cannot check headers
  }

  return findings;
}

// ─── Endpoint Probe ──────────────────────────────────────────────────────────

async function probeEndpoint(card: AgentCard, extraHeaders: Record<string, string> = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  const agentUrl = card.url;
  if (!agentUrl) return findings;

  try {
    // Try sending a minimal tasks/send to see if the agent validates properly
    const res = await fetch(agentUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...extraHeaders },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'security-probe-1',
        method: 'tasks/send',
        params: {
          id: 'probe-' + Date.now(),
          message: { role: 'user', parts: [{ kind: 'text', text: 'ping' }] },
        },
      }),
    });

    if (res.ok) {
      // Agent accepted the request without authentication
      findings.push({
        category: 'Authentication',
        severity: 'high',
        title: 'Agent accepts unauthenticated requests',
        description: 'The agent endpoint accepted a task request without any authentication credentials.',
        recommendation: 'Implement authentication for the agent endpoint.',
      });
    }

    // Check if agent returns error info that reveals internals
    const body = await res.text();
    try {
      const json = JSON.parse(body);
      if (json.error?.data?.stack || json.error?.data?.trace) {
        findings.push({
          category: 'Information Leakage',
          severity: 'medium',
          title: 'Agent leaks stack trace in error response',
          description: 'Error responses include stack traces that could help attackers.',
          evidence: '[stack trace detected]',
          recommendation: 'Sanitize error responses to remove internal details.',
        });
      }
    } catch { /* not JSON */ }
  } catch {
    // Cannot reach endpoint
  }

  return findings;
}

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const { agentUrl, authType, authValue, authHeader, customHeaders } = await request.json();

    if (!agentUrl) {
      return NextResponse.json({ error: 'Agent URL required' }, { status: 400 });
    }

    // Build auth headers
    const reqHeaders: Record<string, string> = {};
    if (authType && authType !== 'none' && authValue) {
      if (authType === 'api_key') {
        reqHeaders[authHeader || 'Authorization'] = authValue;
      } else if (authType === 'bearer') {
        reqHeaders[authHeader || 'Authorization'] = `Bearer ${authValue}`;
      } else if (authType === 'basic') {
        reqHeaders[authHeader || 'Authorization'] = `Basic ${Buffer.from(authValue).toString('base64')}`;
      }
    }

    // Apply custom headers
    if (Array.isArray(customHeaders)) {
      for (const h of customHeaders) {
        if (h.key && h.value) reqHeaders[h.key] = h.value;
      }
    }

    // Fetch agent card
    let card: AgentCard;
    let resolvedUrl: string;
    let legacyPath = false;

    try {
      const result = await fetchAgentCard(agentUrl, reqHeaders);
      card = result.card;
      resolvedUrl = result.resolvedUrl;
      legacyPath = result.legacyPath;
    } catch {
      return NextResponse.json({
        error: 'Could not fetch agent card',
        findings: [{
          category: 'Connectivity',
          severity: 'high',
          title: 'Agent card not found',
          description: 'Could not retrieve the agent card from the provided URL or well-known paths.',
          evidence: agentUrl,
          recommendation: 'Ensure the agent serves its card at the provided URL or at /.well-known/agent.json.',
        }],
        summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
      });
    }

    // Run all analyses
    const findings: Finding[] = [];

    // Discovery path: flag legacy-only well-known location.
    if (legacyPath) {
      findings.push({
        category: 'Spec Compliance',
        severity: 'low',
        title: 'Agent card served only at the legacy well-known path',
        description: 'The agent card was found at /.well-known/agent.json. Current A2A revisions define the canonical discovery path as /.well-known/agent-card.json. Clients following the current spec may fail to discover this agent.',
        evidence: resolvedUrl,
        recommendation: 'Serve the agent card at /.well-known/agent-card.json (a redirect or copy from the legacy path is acceptable for compatibility).',
      });
    }

    findings.push(...analyzeSpecCompliance(card, resolvedUrl));
    findings.push(...analyzeAuthentication(card, resolvedUrl));
    findings.push(...analyzeCardSignature(card));
    findings.push(...analyzeTransports(card));
    findings.push(...analyzeExtensions(card));
    findings.push(...analyzeAuxiliaryUrls(card));
    findings.push(...analyzeEndpointSecurity(resolvedUrl));
    findings.push(...analyzeInjectionRisks(card));
    findings.push(...analyzeSecretLeakage(card));
    findings.push(...analyzeProviderInfo(card));
    findings.push(...analyzeCapabilities(card));
    findings.push(...await analyzeSecurityHeaders(resolvedUrl, reqHeaders));
    findings.push(...await probeEndpoint(card, reqHeaders));

    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length,
    };

    const categories = [...new Set(findings.map(f => f.category))].map(cat => ({
      name: cat,
      count: findings.filter(f => f.category === cat).length,
    }));

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      agentUrl,
      resolvedUrl,
      agentName: card.name || 'Unknown',
      agentVersion: card.version || null,
      skillsCount: card.skills?.length || 0,
      findings,
      summary,
      categories,
      raw: { agentCard: card },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Security scan failed' },
      { status: 500 }
    );
  }
}
