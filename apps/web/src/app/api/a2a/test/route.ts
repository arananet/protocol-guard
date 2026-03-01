import { NextRequest, NextResponse } from 'next/server';

// A2A spec URLs and versions
const A2A_SPEC = {
  version: '2025-01-17',
  urls: {
    base: 'https://a2a-protocol.org',
    agentCard: 'https://a2a-protocol.org/latest/',
    authentication: 'https://a2a-protocol.org/latest/',
    skills: 'https://a2a-protocol.org/latest/',
  },
};

// A2A compliance rules
const A2A_COMPLIANCE_RULES = [
  { id: 'agent-card-name', name: 'Agent Name', severity: 'critical' },
  { id: 'agent-card-description', name: 'Agent Description', severity: 'critical' },
  { id: 'agent-card-url', name: 'Agent URL', severity: 'critical' },
  { id: 'agent-card-version', name: 'Version', severity: 'critical' },
  { id: 'agent-card-capabilities', name: 'Capabilities', severity: 'warning' },
  { id: 'agent-card-skills', name: 'Skills Declaration', severity: 'warning' },
  { id: 'agent-card-input-modes', name: 'Default Input Modes', severity: 'info' },
  { id: 'agent-card-output-modes', name: 'Default Output Modes', severity: 'info' },
  { id: 'agent-card-authentication', name: 'Authentication', severity: 'critical' },
];

function isValidURL(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/** Try to fetch agent card from multiple well-known paths */
async function fetchAgentCard(
  baseUrl: string,
  headers: Record<string, string>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<{ card: any; resolvedUrl: string; error?: string }> {
  const urlObj = new URL(baseUrl);
  
  // Build list of URLs to try:
  // 1. The exact URL provided
  // 2. /.well-known/agent.json appended to the origin/path
  // 3. /agent.json appended to the origin/path
  const urlsToTry: string[] = [baseUrl];

  // If the URL doesn't already end with .json, try well-known paths
  if (!baseUrl.endsWith('.json')) {
    const base = urlObj.origin + urlObj.pathname.replace(/\/+$/, '');
    urlsToTry.push(`${base}/.well-known/agent.json`);
    urlsToTry.push(`${urlObj.origin}/.well-known/agent.json`);
  }

  const errors: string[] = [];

  for (const url of urlsToTry) {
    try {
      const response = await fetch(url, { 
        headers: { ...headers, 'Accept': 'application/json' },
        // Use GET for agent card discovery (it's a resource, not an RPC call)
      });

      if (!response.ok) {
        errors.push(`${url} → HTTP ${response.status}`);
        continue;
      }

      const contentType = response.headers.get('content-type') || '';
      const text = await response.text();

      // Try to parse as JSON
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        errors.push(`${url} → Response is not valid JSON`);
        continue;
      }

      // Validate it looks like an agent card (has at least a name or description)
      if (json && (json.name || json.description || json.url || json.skills)) {
        return { card: json, resolvedUrl: url };
      }

      // Might be HTML or some other response — keep trying
      if (contentType.includes('text/html')) {
        errors.push(`${url} → Returned HTML, not JSON`);
        continue;
      }

      // Got JSON but doesn't look like an agent card — still return it
      return { card: json, resolvedUrl: url };
    } catch (err) {
      errors.push(`${url} → ${err instanceof Error ? err.message : 'fetch failed'}`);
    }
  }

  return { card: null, resolvedUrl: baseUrl, error: `Could not fetch agent card. Tried: ${errors.join('; ')}` };
}

export async function POST(request: NextRequest) {
  try {
    const { agentCardUrl, authType, authValue, authHeader } = await request.json();

    if (!agentCardUrl) {
      return NextResponse.json({ error: 'Agent Card URL required' }, { status: 400 });
    }

    // Build headers for authenticated requests
    const headers: Record<string, string> = {};
    if (authType && authType !== 'none' && authValue) {
      if (authType === 'api_key') {
        headers[authHeader || 'Authorization'] = authValue;
      } else if (authType === 'bearer') {
        headers[authHeader || 'Authorization'] = `Bearer ${authValue}`;
      } else if (authType === 'basic') {
        headers[authHeader || 'Authorization'] = `Basic ${Buffer.from(authValue).toString('base64')}`;
      }
    }

    // Fetch agent card (tries multiple well-known paths)
    const { card: agentCard, resolvedUrl, error: fetchError } = await fetchAgentCard(agentCardUrl, headers);

    if (!agentCard) {
      return NextResponse.json({
        timestamp: new Date().toISOString(),
        protocolVersion: A2A_SPEC.version,
        specUrl: A2A_SPEC.urls.base,
        agentName: 'Unknown',
        results: [{
          passed: false,
          ruleId: 'agent-card-fetch',
          message: fetchError || 'Could not fetch agent card from the provided URL.',
          severity: 'critical',
          docUrl: A2A_SPEC.urls.agentCard,
        }],
        passedCount: 0,
        failedCount: 1,
        warningCount: 0,
        agentCard: null,
        resolvedUrl,
      });
    }

    // Run compliance checks
    const results = A2A_COMPLIANCE_RULES.map((rule) => {
      let passed = false;
      let message = '';
      let docUrl = '';

      switch (rule.id) {
        case 'agent-card-name':
          passed = !!agentCard?.name;
          message = passed ? `Agent name present: "${agentCard.name}"` : 'MISSING: Agent card must have "name" field.';
          if (!passed) docUrl = A2A_SPEC.urls.agentCard;
          break;
        case 'agent-card-description':
          passed = !!agentCard?.description;
          message = passed ? `Agent description present` : 'MISSING: Agent card must have "description" field.';
          if (!passed) docUrl = A2A_SPEC.urls.agentCard;
          break;
        case 'agent-card-url':
          passed = isValidURL(agentCard?.url);
          message = passed ? `Agent URL valid: ${agentCard.url}` : 'MISSING: Agent card must have valid "url" field.';
          if (!passed) docUrl = A2A_SPEC.urls.agentCard;
          break;
        case 'agent-card-version':
          passed = !!agentCard?.version;
          message = passed ? `Version present: ${agentCard.version}` : 'MISSING: Agent card must have "version" field.';
          if (!passed) docUrl = A2A_SPEC.urls.agentCard;
          break;
        case 'agent-card-capabilities':
          passed = !!agentCard?.capabilities;
          message = passed ? 'Capabilities declared' : 'MISSING: Agent card should declare "capabilities".';
          if (!passed) docUrl = A2A_SPEC.urls.agentCard;
          break;
        case 'agent-card-skills':
          passed = Array.isArray(agentCard?.skills) && agentCard.skills.length > 0;
          if (passed) {
            message = `${agentCard.skills.length} skill(s) declared: ${agentCard.skills.map((s: { name?: string; id?: string }) => s.name || s.id).join(', ')}`;
          } else {
            message = 'MISSING: Agent card should declare "skills" array with at least one skill.';
            docUrl = A2A_SPEC.urls.skills;
          }
          break;
        case 'agent-card-input-modes':
          passed = Array.isArray(agentCard?.defaultInputModes) && agentCard.defaultInputModes.length > 0;
          if (passed) {
            message = `Input modes: ${agentCard.defaultInputModes.join(', ')}`;
          } else {
            message = 'Not declared: "defaultInputModes" helps clients know accepted input formats.';
            docUrl = A2A_SPEC.urls.agentCard;
          }
          break;
        case 'agent-card-output-modes':
          passed = Array.isArray(agentCard?.defaultOutputModes) && agentCard.defaultOutputModes.length > 0;
          if (passed) {
            message = `Output modes: ${agentCard.defaultOutputModes.join(', ')}`;
          } else {
            message = 'Not declared: "defaultOutputModes" helps clients know response formats.';
            docUrl = A2A_SPEC.urls.agentCard;
          }
          break;
        case 'agent-card-authentication':
          passed = !!(agentCard?.authentication?.schemes?.length > 0);
          message = passed
            ? `Authentication schemes: ${agentCard.authentication.schemes.join(', ')}`
            : 'MISSING: Agent card must declare "authentication" with schemes.';
          if (!passed) docUrl = A2A_SPEC.urls.authentication;
          break;
      }

      return { passed, ruleId: rule.id, message, severity: rule.severity, docUrl: docUrl || undefined };
    });

    const passedCount = results.filter((r) => r.passed).length;
    const failedCount = results.filter((r) => !r.passed && r.severity === 'critical').length;
    const warningCount = results.filter((r) => !r.passed && (r.severity === 'warning' || r.severity === 'info')).length;

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      protocolVersion: A2A_SPEC.version,
      specUrl: A2A_SPEC.urls.base,
      agentName: agentCard?.name || 'Unknown',
      results,
      passedCount,
      failedCount,
      warningCount,
      agentCard: agentCard || null,
      resolvedUrl,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Validation failed' },
      { status: 500 }
    );
  }
}
