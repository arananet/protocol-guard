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

interface AgentCard {
  name?: string;
  description?: string;
  url?: string;
  version?: string;
  capabilities?: {
    streaming?: boolean;
    pushNotifications?: boolean;
    stateTransitionHistory?: boolean;
  };
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
  }>;
  provider?: {
    organization?: string;
    url?: string;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

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

  if (!card.authentication || !card.authentication.schemes || card.authentication.schemes.length === 0) {
    findings.push({
      category: 'Authentication',
      severity: 'high',
      title: 'No authentication scheme declared',
      description: 'The agent card does not specify any authentication mechanism. The agent endpoint may be publicly accessible without authentication.',
      recommendation: 'Implement authentication (e.g., OAuth2, API key, bearer token) and declare it in the agent card.',
    });
  }

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

async function fetchAgentCard(url: string): Promise<{ card: AgentCard; resolvedUrl: string }> {
  const attempts = [
    url,
    url.replace(/\/$/, '') + '/.well-known/agent.json',
    new URL('/.well-known/agent.json', url).toString(),
  ];

  const uniqueAttempts = [...new Set(attempts)];

  for (const attempt of uniqueAttempts) {
    try {
      const res = await fetch(attempt, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        if (data && typeof data === 'object' && (data.name || data.skills || data.url)) {
          return { card: data, resolvedUrl: attempt };
        }
      }
    } catch { /* try next */ }
  }

  throw new Error('Could not fetch agent card from any well-known location');
}

// ─── Security Headers Check ──────────────────────────────────────────────────

async function analyzeSecurityHeaders(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const res = await fetch(url, { method: 'GET', headers: { 'Accept': 'application/json' } });
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

async function probeEndpoint(card: AgentCard): Promise<Finding[]> {
  const findings: Finding[] = [];
  const agentUrl = card.url;
  if (!agentUrl) return findings;

  try {
    // Try sending a minimal tasks/send to see if the agent validates properly
    const res = await fetch(agentUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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
    const { agentUrl } = await request.json();

    if (!agentUrl) {
      return NextResponse.json({ error: 'Agent URL required' }, { status: 400 });
    }

    // Fetch agent card
    let card: AgentCard;
    let resolvedUrl: string;

    try {
      const result = await fetchAgentCard(agentUrl);
      card = result.card;
      resolvedUrl = result.resolvedUrl;
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

    findings.push(...analyzeSpecCompliance(card, resolvedUrl));
    findings.push(...analyzeAuthentication(card, resolvedUrl));
    findings.push(...analyzeEndpointSecurity(resolvedUrl));
    findings.push(...analyzeInjectionRisks(card));
    findings.push(...analyzeSecretLeakage(card));
    findings.push(...analyzeProviderInfo(card));
    findings.push(...analyzeCapabilities(card));
    findings.push(...await analyzeSecurityHeaders(resolvedUrl));
    findings.push(...await probeEndpoint(card));

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
