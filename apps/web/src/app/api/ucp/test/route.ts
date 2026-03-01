import { NextRequest, NextResponse } from 'next/server';

// UCP spec reference
const UCP_SPEC = {
  latestVersion: '2026-01-23',
  specUrl: 'https://ucp.dev/latest/specification/overview',
  repoUrl: 'https://github.com/Universal-Commerce-Protocol/ucp',
};

const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const NAMESPACE_REGEX = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2,}$/;

interface ComplianceResult {
  passed: boolean;
  ruleId: string;
  message: string;
  severity: 'critical' | 'warning' | 'info';
  docUrl?: string;
  details?: Record<string, unknown>;
}

/**
 * Run all UCP compliance checks against a fetched business profile.
 */
function runComplianceChecks(profile: Record<string, unknown>): ComplianceResult[] {
  const results: ComplianceResult[] = [];
  const specBase = UCP_SPEC.specUrl;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ucp = profile.ucp as any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const signingKeys = profile.signing_keys as any[];

  // ── 1. Profile root object ──────────────────────────────────────────
  results.push({
    passed: !!ucp && typeof ucp === 'object',
    ruleId: 'ucp-profile-root',
    message: ucp ? 'Top-level "ucp" object present' : 'Missing top-level "ucp" object in the profile',
    severity: 'critical',
    docUrl: `${specBase}#business-profile`,
  });

  if (!ucp || typeof ucp !== 'object') return results; // can't continue

  // ── 2. UCP version ──────────────────────────────────────────────────
  const version = ucp.version;
  const versionValid = !!version && DATE_REGEX.test(version);
  results.push({
    passed: versionValid,
    ruleId: 'ucp-version',
    message: versionValid
      ? `UCP version: ${version}`
      : version
        ? `Invalid version format "${version}" — expected YYYY-MM-DD`
        : 'Missing ucp.version field',
    severity: 'critical',
    details: { version },
    docUrl: `${specBase}#versioning`,
  });

  // ── 3. Services present ─────────────────────────────────────────────
  const services = ucp.services as Record<string, Record<string, unknown>> | undefined;
  const serviceKeys = services && typeof services === 'object' ? Object.keys(services) : [];
  results.push({
    passed: serviceKeys.length > 0,
    ruleId: 'ucp-services-present',
    message: serviceKeys.length > 0
      ? `${serviceKeys.length} service(s) declared: ${serviceKeys.join(', ')}`
      : 'Missing or empty ucp.services object',
    severity: 'critical',
    docUrl: `${specBase}#services`,
  });

  // ── 4. Service namespace ────────────────────────────────────────────
  const invalidServiceNs = serviceKeys.filter(k => !NAMESPACE_REGEX.test(k));
  results.push({
    passed: invalidServiceNs.length === 0 && serviceKeys.length > 0,
    ruleId: 'ucp-service-namespace',
    message: invalidServiceNs.length === 0
      ? 'All service keys follow reverse-domain notation'
      : `Invalid service namespace(s): ${invalidServiceNs.join(', ')}`,
    severity: 'critical',
    details: { invalidKeys: invalidServiceNs },
    docUrl: `${specBase}#namespace-governance`,
  });

  // ── 5. Service version ──────────────────────────────────────────────
  if (services && serviceKeys.length > 0) {
    const badVersionSvc = serviceKeys.filter(k => {
      const s = services[k];
      return !s?.version || !DATE_REGEX.test(String(s.version));
    });
    results.push({
      passed: badVersionSvc.length === 0,
      ruleId: 'ucp-service-version',
      message: badVersionSvc.length === 0
        ? 'All services have valid YYYY-MM-DD versions'
        : `${badVersionSvc.length} service(s) missing valid version: ${badVersionSvc.join(', ')}`,
      severity: 'critical',
      details: { invalid: badVersionSvc },
      docUrl: `${specBase}#services`,
    });

    // ── 6. Service spec URL ─────────────────────────────────────────
    const missingSpec = serviceKeys.filter(k => !services[k]?.spec);
    results.push({
      passed: missingSpec.length === 0,
      ruleId: 'ucp-service-spec',
      message: missingSpec.length === 0
        ? 'All services have spec URLs'
        : `${missingSpec.length} service(s) missing spec URL: ${missingSpec.join(', ')}`,
      severity: 'critical',
      details: { missing: missingSpec },
      docUrl: `${specBase}#services`,
    });

    // ── 7. Transport bindings ───────────────────────────────────────
    const noTransport = serviceKeys.filter(k => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const t = (services[k] as any)?.transport;
      if (!t || typeof t !== 'object') return true;
      return !(t.rest || t.mcp || t.a2a || t.embedded);
    });
    const transportsInfo = serviceKeys.map(k => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const t = (services[k] as any)?.transport || {};
      return {
        name: k,
        rest: !!t.rest,
        mcp: !!t.mcp,
        a2a: !!t.a2a,
        embedded: !!t.embedded,
      };
    });
    results.push({
      passed: noTransport.length === 0,
      ruleId: 'ucp-service-transport',
      message: noTransport.length === 0
        ? 'All services have transport bindings'
        : `${noTransport.length} service(s) missing transport bindings: ${noTransport.join(', ')}`,
      severity: 'critical',
      details: { transports: transportsInfo },
      docUrl: `${specBase}#transport-layer`,
    });

    // ── 8. HTTPS endpoints ──────────────────────────────────────────
    const insecure: string[] = [];
    for (const k of serviceKeys) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const t = (services[k] as any)?.transport;
      if (!t) continue;
      if (t.rest?.endpoint && !String(t.rest.endpoint).startsWith('https://')) insecure.push(`${k} REST`);
      if (t.mcp?.endpoint && !String(t.mcp.endpoint).startsWith('https://')) insecure.push(`${k} MCP`);
      if (t.a2a?.endpoint && !String(t.a2a.endpoint).startsWith('https://')) insecure.push(`${k} A2A`);
    }
    results.push({
      passed: insecure.length === 0,
      ruleId: 'ucp-endpoints-https',
      message: insecure.length === 0
        ? 'All transport endpoints use HTTPS'
        : `Non-HTTPS endpoint(s): ${insecure.join(', ')}`,
      severity: 'critical',
      details: { insecure },
      docUrl: `${specBase}#security`,
    });
  }

  // ── 9. Capabilities present ─────────────────────────────────────────
  const caps = ucp.capabilities as Record<string, Record<string, unknown>> | undefined;
  const capKeys = caps && typeof caps === 'object' ? Object.keys(caps) : [];
  results.push({
    passed: capKeys.length > 0,
    ruleId: 'ucp-capabilities-present',
    message: capKeys.length > 0
      ? `${capKeys.length} capability(ies) declared: ${capKeys.join(', ')}`
      : 'Missing or empty ucp.capabilities object',
    severity: 'critical',
    details: { count: capKeys.length },
    docUrl: `${specBase}#capabilities`,
  });

  // ── 10. Capability namespace ────────────────────────────────────────
  const invalidCapNs = capKeys.filter(k => !NAMESPACE_REGEX.test(k));
  results.push({
    passed: invalidCapNs.length === 0 && capKeys.length > 0,
    ruleId: 'ucp-capability-namespace',
    message: invalidCapNs.length === 0
      ? 'All capability keys follow reverse-domain notation'
      : `Invalid capability namespace(s): ${invalidCapNs.join(', ')}`,
    severity: 'critical',
    details: { invalidKeys: invalidCapNs },
    docUrl: `${specBase}#namespace-governance`,
  });

  if (caps && capKeys.length > 0) {
    // ── 11. Capability version ────────────────────────────────────────
    const badVersionCap = capKeys.filter(k => {
      const c = caps[k];
      return !c?.version || !DATE_REGEX.test(String(c.version));
    });
    results.push({
      passed: badVersionCap.length === 0,
      ruleId: 'ucp-capability-version',
      message: badVersionCap.length === 0
        ? 'All capabilities have valid YYYY-MM-DD versions'
        : `${badVersionCap.length} capability(ies) missing valid version`,
      severity: 'critical',
      details: { invalid: badVersionCap },
      docUrl: `${specBase}#capabilities`,
    });

    // ── 12. Capability spec URL ───────────────────────────────────────
    const missingCapSpec = capKeys.filter(k => !caps[k]?.spec);
    results.push({
      passed: missingCapSpec.length === 0,
      ruleId: 'ucp-capability-spec',
      message: missingCapSpec.length === 0
        ? 'All capabilities have spec URLs'
        : `${missingCapSpec.length} capability(ies) missing spec URL`,
      severity: 'critical',
      details: { missing: missingCapSpec },
      docUrl: `${specBase}#capabilities`,
    });

    // ── 13. Capability schema URL ─────────────────────────────────────
    const missingCapSchema = capKeys.filter(k => !caps[k]?.schema);
    results.push({
      passed: missingCapSchema.length === 0,
      ruleId: 'ucp-capability-schema',
      message: missingCapSchema.length === 0
        ? 'All capabilities have schema URLs'
        : `${missingCapSchema.length} capability(ies) missing schema URL`,
      severity: 'critical',
      details: { missing: missingCapSchema },
      docUrl: `${specBase}#capabilities`,
    });

    // ── 14. Extension validity ────────────────────────────────────────
    const extensions = capKeys.filter(k => caps[k]?.extends);
    if (extensions.length > 0) {
      const capKeySet = new Set(capKeys);
      const orphans = extensions.filter(k => !capKeySet.has(String(caps[k]!.extends)));
      results.push({
        passed: orphans.length === 0,
        ruleId: 'ucp-capability-extends',
        message: orphans.length === 0
          ? `${extensions.length} extension(s) all reference valid parents`
          : `Orphan extension(s): ${orphans.join(', ')}`,
        severity: 'warning',
        details: { orphans: orphans.map(k => ({ key: k, extends: caps[k]?.extends })) },
        docUrl: `${specBase}#extensions`,
      });
    }
  }

  // ── 15. Payment handlers ────────────────────────────────────────────
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handlers = ucp.payment_handlers as Record<string, any> | undefined;
  if (handlers && typeof handlers === 'object' && Object.keys(handlers).length > 0) {
    const handlerKeys = Object.keys(handlers);
    const badHandlers = handlerKeys.filter(k => {
      const h = handlers[k];
      return !h?.version || !h?.spec || !h?.schema;
    });
    results.push({
      passed: badHandlers.length === 0,
      ruleId: 'ucp-payment-handlers',
      message: badHandlers.length === 0
        ? `${handlerKeys.length} payment handler(s) fully specified`
        : `${badHandlers.length} payment handler(s) missing required fields`,
      severity: 'warning',
      details: { total: handlerKeys.length, invalid: badHandlers },
      docUrl: `${specBase}#payment-architecture`,
    });
  } else {
    results.push({
      passed: true,
      ruleId: 'ucp-payment-handlers',
      message: 'No payment handlers declared (optional)',
      severity: 'info',
    });
  }

  // ── 16. Signing keys ───────────────────────────────────────────────
  if (Array.isArray(signingKeys) && signingKeys.length > 0) {
    const badKeys = signingKeys.filter(k => !k?.kty);
    results.push({
      passed: badKeys.length === 0,
      ruleId: 'ucp-signing-keys',
      message: badKeys.length === 0
        ? `${signingKeys.length} signing key(s) in valid JWK format`
        : `${badKeys.length} signing key(s) missing kty field`,
      severity: 'info',
      details: { count: signingKeys.length },
      docUrl: `${specBase}#security`,
    });
  } else {
    results.push({
      passed: true,
      ruleId: 'ucp-signing-keys',
      message: 'No signing keys declared (optional, used for webhook verification)',
      severity: 'info',
    });
  }

  // ── 17. Spec-binding check ──────────────────────────────────────────
  if (services && serviceKeys.length > 0) {
    const mismatches: string[] = [];
    for (const k of serviceKeys) {
      const specUrl = services[k]?.spec;
      if (specUrl && typeof specUrl === 'string') {
        try {
          const specHost = new URL(specUrl).hostname;
          const parts = k.split('.');
          const authority = parts.length >= 2 ? `${parts[1]}.${parts[0]}` : '';
          if (authority && !specHost.endsWith(authority)) {
            mismatches.push(`${k} → ${specHost}`);
          }
        } catch { /* skip invalid URLs */ }
      }
    }
    results.push({
      passed: mismatches.length === 0,
      ruleId: 'ucp-spec-binding',
      message: mismatches.length === 0
        ? 'All spec URLs match their namespace authority'
        : `Mismatched spec binding(s): ${mismatches.join('; ')}`,
      severity: 'warning',
      details: { mismatches },
      docUrl: `${specBase}#namespace-governance`,
    });
  }

  // ── 18. Vendor namespace info ───────────────────────────────────────
  if (capKeys.length > 0) {
    const standard = capKeys.filter(k => k.startsWith('dev.ucp.'));
    const vendor = capKeys.filter(k => !k.startsWith('dev.ucp.'));
    results.push({
      passed: true,
      ruleId: 'ucp-vendor-namespace',
      message: vendor.length > 0
        ? `${vendor.length} vendor capability(ies), ${standard.length} standard (dev.ucp.*)`
        : `All ${standard.length} capability(ies) use standard dev.ucp.* namespace`,
      severity: 'info',
      details: { standard: standard.length, vendor: vendor.length },
      docUrl: `${specBase}#namespace-governance`,
    });
  }

  return results;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { endpoint, authType, authValue, authHeader } = body;

    if (!endpoint) {
      return NextResponse.json({ error: 'Endpoint URL required' }, { status: 400 });
    }

    // Normalise base URL (strip trailing slash)
    const baseUrl = endpoint.replace(/\/+$/, '');
    const profileUrl = `${baseUrl}/.well-known/ucp`;

    // Build request headers
    const headers: Record<string, string> = {
      'Accept': 'application/json',
    };

    if (authType === 'bearer' && authValue) {
      headers[authHeader || 'Authorization'] = `Bearer ${authValue}`;
    } else if (authType === 'basic' && authValue) {
      headers[authHeader || 'Authorization'] = `Basic ${Buffer.from(authValue).toString('base64')}`;
    } else if (authType === 'api_key' && authValue) {
      headers[authHeader || 'X-API-Key'] = authValue;
    }

    // ── Fetch the UCP Business Profile from /.well-known/ucp ─────────
    let profileData: Record<string, unknown>;
    let fetchError: string | null = null;
    let httpStatus: number | null = null;
    const responseHeaders: Record<string, string> = {};

    try {
      const response = await fetch(profileUrl, { method: 'GET', headers });
      httpStatus = response.status;

      // Capture response headers
      response.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });

      if (!response.ok) {
        fetchError = `HTTP ${response.status} ${response.statusText}`;
        profileData = {};
      } else {
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('json')) {
          fetchError = `Expected JSON response but got: ${contentType}`;
          profileData = {};
        } else {
          profileData = (await response.json()) as Record<string, unknown>;
        }
      }
    } catch (err) {
      fetchError = err instanceof Error ? err.message : 'Network error';
      profileData = {};
    }

    // ── Discovery check (can we reach /.well-known/ucp?) ─────────────
    const discoveryResult: ComplianceResult = {
      passed: !fetchError,
      ruleId: 'ucp-discovery',
      message: fetchError
        ? `Failed to fetch ${profileUrl}: ${fetchError}`
        : `Business profile discovered at ${profileUrl}`,
      severity: 'critical',
      details: { url: profileUrl, httpStatus },
      docUrl: `${UCP_SPEC.specUrl}#discovery`,
    };

    // ── Content-Type check ────────────────────────────────────────────
    const ct = responseHeaders['content-type'] || '';
    const contentTypeResult: ComplianceResult = {
      passed: ct.includes('application/json'),
      ruleId: 'ucp-content-type',
      message: ct.includes('application/json')
        ? 'Response Content-Type is application/json'
        : `Expected application/json but got: ${ct || '(none)'}`,
      severity: 'warning',
      docUrl: `${UCP_SPEC.specUrl}#business-profile`,
    };

    // ── Run structural compliance checks ──────────────────────────────
    const structuralResults = fetchError ? [] : runComplianceChecks(profileData);

    const allResults = [discoveryResult, contentTypeResult, ...structuralResults];

    const passedCount = allResults.filter(r => r.passed).length;
    const failedCount = allResults.filter(r => !r.passed && r.severity === 'critical').length;
    const warningCount = allResults.filter(r => !r.passed && r.severity === 'warning').length;

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      specVersion: UCP_SPEC.latestVersion,
      specUrl: UCP_SPEC.specUrl,
      repoUrl: UCP_SPEC.repoUrl,
      profileUrl,
      results: allResults,
      passedCount,
      failedCount,
      warningCount,
      rawProfile: Object.keys(profileData).length > 0 ? profileData : null,
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Test failed' },
      { status: 500 }
    );
  }
}
