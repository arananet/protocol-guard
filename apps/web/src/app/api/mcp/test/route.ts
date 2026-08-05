import { NextRequest, NextResponse } from 'next/server';
import {
  MCP_DEPRECATED_VERSIONS,
  MCP_ERROR_CODES,
  MCP_KNOWN_VERSIONS,
  MCP_LATEST_VERSION,
  MCP_LEGACY_VERSIONS,
  MCP_META_KEYS,
  MCP_MODERN_VERSIONS,
  MCP_SPEC_URLS,
  buildBaseHeaders,
  cacheHintsOf,
  connectMCP,
  mcpCall,
  modernCall,
  modernHeaders,
  parseMCPResponse,
  resultTypeOf,
  withRequestMeta,
  type Json,
  type MCPConnection,
} from '@/lib/mcp';

/**
 * MCP compliance tester.
 *
 * The scanner speaks the latest revision (2026-07-28) first and falls back to
 * the handshake era only when the server turns out to be legacy, so the rules
 * below are selected per era: a stateless server is graded on `server/discover`,
 * `resultType`, cache hints and mirrored headers, while a handshake server is
 * still graded on `initialize` / `ping` and told which era it is in.
 */

type Severity = 'critical' | 'warning' | 'info';

interface RuleResult {
  passed: boolean;
  ruleId: string;
  message: string;
  severity: Severity;
  docUrl?: string;
  note?: string;
}

interface ProbeResults {
  toolsList: { ran: boolean; ok: boolean; result: Json; resultType?: string };
  headerValidation: { ran: boolean; status: number; errorCode?: number; accepted: boolean };
  getMethod: { ran: boolean; status: number };
  ping: { ran: boolean; ok: boolean; message: string };
}

export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader, customHeaders } = await request.json();

    if (!serverUrl) {
      return NextResponse.json({ error: 'Server URL required' }, { status: 400 });
    }

    const baseHeaders = buildBaseHeaders({ authType, authValue, authHeader, customHeaders });

    const conn = await connectMCP(serverUrl, baseHeaders);

    const probes: ProbeResults = {
      toolsList: { ran: false, ok: false, result: null },
      headerValidation: { ran: false, status: 0, accepted: false },
      getMethod: { ran: false, status: 0 },
      ping: { ran: false, ok: false, message: '' },
    };

    if (conn.era !== 'unknown') {
      const tools = await mcpCall(conn, serverUrl, baseHeaders, 'tools/list');
      probes.toolsList = {
        ran: true,
        ok: !tools.error && tools.raw?.result !== undefined,
        result: tools.result,
        resultType: resultTypeOf(tools.result),
      };
    }

    if (conn.era === 'modern') {
      await probeHeaderValidation(serverUrl, baseHeaders, conn, probes);
      await probeGetRejection(serverUrl, baseHeaders, probes);
    }

    if (conn.era === 'legacy') {
      const ping = await mcpCall(conn, serverUrl, baseHeaders, 'ping');
      probes.ping = {
        ran: true,
        ok: !ping.error && ping.raw?.result !== undefined,
        message: ping.error
          ? `Server returned error for ping: ${ping.error.message || 'method not found'}`
          : ping.raw?.result !== undefined
            ? 'Server responds to JSON-RPC "ping" method'
            : ping.transportError || 'Unexpected response format for ping method',
      };
    }

    const authOutcome = evaluateAuth(conn, authType);
    const results =
      conn.era === 'legacy'
        ? legacyRules(conn, probes, authOutcome)
        : modernRules(conn, probes, authOutcome);

    const passedCount = results.filter((r) => r.passed).length;
    const failedCount = results.filter((r) => !r.passed && r.severity === 'critical').length;
    const warningCount = results.filter((r) => !r.passed && r.severity === 'warning').length;

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      protocolVersion: conn.protocolVersion || MCP_LATEST_VERSION,
      requestedVersion: MCP_LATEST_VERSION,
      latestVersion: MCP_LATEST_VERSION,
      protocolEra: conn.era,
      supportedVersions: conn.supportedVersions || null,
      specUrl: MCP_SPEC_URLS.spec,
      serverName: conn.serverInfo?.name || 'Unknown',
      results,
      passedCount,
      failedCount,
      warningCount,
      serverResponse: conn.raw || (conn.error ? { _error: conn.error } : null),
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Test failed' },
      { status: 500 }
    );
  }
}

// ─── Live probes (modern era only) ──────────────────────────────────────────

/**
 * `Mcp-Method` must mirror the body's `method`. A conforming server rejects a
 * mismatch with `400 Bad Request` and a `HeaderMismatch` (-32020) error.
 */
async function probeHeaderValidation(
  serverUrl: string,
  baseHeaders: Record<string, string>,
  conn: MCPConnection,
  probes: ProbeResults
): Promise<void> {
  const version = conn.protocolVersion || MCP_LATEST_VERSION;
  const params = withRequestMeta({}, version);
  const headers = modernHeaders(baseHeaders, version, 'tools/list', params);
  headers['Mcp-Method'] = 'resources/list'; // deliberately disagrees with the body

  const res = await modernCall(serverUrl, baseHeaders, version, 'tools/list', {}, headers);
  probes.headerValidation = {
    ran: true,
    status: res.status,
    errorCode: res.error?.code,
    // The server processed a request whose headers contradicted its body.
    accepted: !res.error && res.raw?.result !== undefined,
  };
}

/** Streamable HTTP no longer has a GET endpoint; a modern server answers 405. */
async function probeGetRejection(
  serverUrl: string,
  baseHeaders: Record<string, string>,
  probes: ProbeResults
): Promise<void> {
  try {
    const res = await fetch(serverUrl, {
      method: 'GET',
      headers: { ...baseHeaders, Accept: 'text/event-stream' },
      signal: AbortSignal.timeout(5000),
    });
    probes.getMethod = { ran: true, status: res.status };
    // Drain so an accidentally-opened SSE stream does not stay pending.
    await parseMCPResponse(res).catch(() => undefined);
  } catch {
    probes.getMethod = { ran: true, status: 0 };
  }
}

// ─── Shared rule builders ────────────────────────────────────────────────────

interface AuthOutcome {
  passed: boolean;
  message: string;
  note?: string;
}

function evaluateAuth(conn: MCPConnection, authType: string | undefined): AuthOutcome {
  if (!authType || authType === 'none') {
    return {
      passed: true,
      message: 'No authentication configured',
      note: `The MCP spec does not mandate authentication but strongly recommends it for any non-local deployment. Running without auth means any client can connect and invoke all tools. Standards guidance: OWASP MCP Top 10 — MCP07 (Insufficient Authentication & Authorization) flags unauthenticated servers as a high-risk finding. MSSS MCP-AUTHZ-01 (L3) requires OAuth 2.1 delegation for production and internet-facing servers. Consider adding Bearer token auth at minimum for team/internal use, or OAuth 2.1 for production.`,
    };
  }

  if (conn.status === 401 || conn.status === 403) {
    return { passed: false, message: `AUTH FAILED: Server returned ${conn.status}.` };
  }

  if (conn.era === 'unknown') {
    return { passed: true, message: `Authentication (${authType}) configured but couldn't verify` };
  }

  return { passed: true, message: `Authentication (${authType}) accepted` };
}

function versionRule(conn: MCPConnection): RuleResult {
  const negotiated = conn.protocolVersion;

  if (!negotiated) {
    return {
      passed: false,
      ruleId: 'protocol-version',
      message: 'MISSING: Could not determine the protocol version the server speaks.',
      severity: 'critical',
      docUrl: MCP_SPEC_URLS.versioning,
    };
  }

  const deprecation = MCP_DEPRECATED_VERSIONS[negotiated];
  const unknown = !MCP_KNOWN_VERSIONS.includes(negotiated);

  if (deprecation) {
    return {
      passed: false,
      ruleId: 'protocol-version',
      message: `Protocol version "${negotiated}" is DEPRECATED — ${deprecation} Upgrade to ${MCP_LATEST_VERSION}.`,
      severity: 'critical',
      docUrl: MCP_SPEC_URLS.versioning,
      note: `Latest is ${MCP_LATEST_VERSION}. Pre-2025-06-18 revisions lack Resource Indicators (RFC 8707) and Protected Resource Metadata (RFC 9728).`,
    };
  }

  if (unknown) {
    return {
      passed: false,
      ruleId: 'protocol-version',
      message: `Protocol version present but unrecognized: "${negotiated}".`,
      severity: 'critical',
      docUrl: MCP_SPEC_URLS.versioning,
    };
  }

  if (MCP_LEGACY_VERSIONS.includes(negotiated)) {
    return {
      passed: true,
      ruleId: 'protocol-version',
      message: `Protocol version present: "${negotiated}" (superseded by ${MCP_LATEST_VERSION})`,
      severity: 'critical',
      docUrl: MCP_SPEC_URLS.versioning,
      note: `${negotiated} is a published revision but predates the stateless model introduced in ${MCP_LATEST_VERSION}.`,
    };
  }

  return {
    passed: true,
    ruleId: 'protocol-version',
    message: `Protocol version present: "${negotiated}"${
      conn.supportedVersions ? ` (server supports ${conn.supportedVersions.join(', ')})` : ''
    }`,
    severity: 'critical',
  };
}

function deprecatedFeatureRule(conn: MCPConnection): RuleResult {
  const caps = conn.capabilities || {};
  const declared = ['roots', 'sampling', 'logging'].filter((f) => caps[f] !== undefined);

  return {
    passed: declared.length === 0,
    ruleId: 'deprecated-features',
    message:
      declared.length === 0
        ? 'No deprecated features declared'
        : `Server declares deprecated capabilities: ${declared.join(', ')}`,
    severity: 'info',
    docUrl: declared.length ? MCP_SPEC_URLS.deprecated : undefined,
    note: declared.length
      ? 'Roots, Sampling and Logging are Deprecated as of 2026-07-28 with a minimum twelve-month removal window. Suggested migrations: pass directories/files as tool parameters or resource URIs instead of Roots, integrate with an LLM provider API directly instead of Sampling, and log to stderr or OpenTelemetry instead of Logging.'
      : undefined,
  };
}

function capabilityRules(conn: MCPConnection): RuleResult[] {
  const caps = conn.capabilities;
  const hasCaps = caps !== null && typeof caps === 'object';

  return [
    {
      passed: hasCaps,
      ruleId: 'capabilities-object',
      message: hasCaps ? 'Capabilities object present' : 'MISSING: Server must return a "capabilities" object.',
      severity: 'warning',
      docUrl: hasCaps ? undefined : MCP_SPEC_URLS.basic,
    },
    {
      passed: true,
      ruleId: 'tools-capability',
      message: caps?.tools ? 'Tools capability declared' : 'Tools not declared (optional)',
      severity: 'info',
    },
    {
      passed: true,
      ruleId: 'resources-capability',
      message: caps?.resources ? 'Resources capability declared' : 'Resources not declared (optional)',
      severity: 'info',
    },
  ];
}

// ─── Modern (2026-07-28) rules ───────────────────────────────────────────────

function modernRules(
  conn: MCPConnection,
  probes: ProbeResults,
  auth: AuthOutcome
): RuleResult[] {
  const results: RuleResult[] = [];

  results.push({
    passed: conn.era === 'modern',
    ruleId: 'protocol-era',
    message:
      conn.era === 'modern'
        ? `Server speaks the stateless protocol (${MCP_MODERN_VERSIONS.join(', ')})`
        : `FAILED: Server answered neither "server/discover" nor "initialize"${
            conn.error ? ` — ${conn.error}` : ''
          }.`,
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.versioning,
    note:
      conn.era === 'modern'
        ? undefined
        : 'The scanner probes server/discover at 2026-07-28 and falls back to the initialize handshake. Verify the URL accepts JSON-RPC POST requests.',
  });

  results.push(versionRule(conn));

  results.push({
    passed: conn.probe.discoverImplemented,
    ruleId: 'server-discover',
    message: conn.probe.discoverImplemented
      ? 'server/discover implemented'
      : 'FAILED: Servers MUST implement "server/discover" to advertise supported versions, capabilities and identity.',
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.discover,
  });

  const supported = conn.supportedVersions;
  results.push({
    passed: Array.isArray(supported) && supported.length > 0,
    ruleId: 'supported-versions',
    message: Array.isArray(supported) && supported.length > 0
      ? `Server advertises supported versions: ${supported.join(', ')}`
      : 'MISSING: server/discover must return "supportedVersions".',
    severity: 'warning',
    docUrl: MCP_SPEC_URLS.discover,
  });

  const hasIdentity = !!(conn.serverInfo?.name && conn.serverInfo?.version);
  results.push({
    passed: hasIdentity,
    ruleId: 'server-info',
    message: hasIdentity
      ? `Server info present: "${conn.serverInfo?.name}" v${conn.serverInfo?.version}`
      : `MISSING: Servers SHOULD identify themselves via "${MCP_META_KEYS.serverInfo}" in each result's _meta.`,
    severity: 'warning',
    docUrl: MCP_SPEC_URLS.basic,
  });

  results.push(...capabilityRules(conn));

  // resultType is required on every result from 2026-07-28.
  const discoverType = resultTypeOf(conn.discover);
  const toolsType = probes.toolsList.resultType;
  const observed = [discoverType, toolsType].filter(Boolean) as string[];
  const missing = (conn.discover && !discoverType) || (probes.toolsList.ok && !toolsType);
  results.push({
    passed: observed.length > 0 && !missing,
    ruleId: 'result-type',
    message: missing
      ? 'MISSING: Results must carry a "resultType" field ("complete" or "input_required").'
      : observed.length > 0
        ? `Results carry resultType: ${[...new Set(observed)].join(', ')}`
        : 'Could not observe a result to check "resultType".',
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.basic,
  });

  // tools/list is a CacheableResult: ttlMs + cacheScope are required.
  const hints = cacheHintsOf(probes.toolsList.result);
  results.push({
    passed: !probes.toolsList.ok || hints.valid,
    ruleId: 'cacheable-results',
    message: !probes.toolsList.ok
      ? 'tools/list not available — cache hints not checked'
      : hints.valid
        ? `Cache hints present on tools/list (ttlMs: ${hints.ttlMs}, cacheScope: ${hints.cacheScope})`
        : `MISSING/INVALID cache hints on tools/list (ttlMs: ${
            hints.hasTtl ? hints.ttlMs : 'absent'
          }, cacheScope: ${hints.hasScope ? hints.cacheScope : 'absent'}).`,
    severity: 'warning',
    docUrl: MCP_SPEC_URLS.caching,
    note: hints.valid
      ? undefined
      : 'Servers MUST include ttlMs (>= 0) and cacheScope ("public" or "private") on complete results from server/discover, tools/list, prompts/list, resources/list, resources/templates/list and resources/read.',
  });

  const hv = probes.headerValidation;
  results.push({
    passed: hv.ran && !hv.accepted,
    ruleId: 'header-validation',
    message: !hv.ran
      ? 'Header validation not tested'
      : hv.accepted
        ? 'FAILED: Server processed a request whose Mcp-Method header contradicted the body.'
        : `Server rejected a mismatched Mcp-Method header (HTTP ${hv.status}${
            hv.errorCode ? `, JSON-RPC ${hv.errorCode}` : ''
          })`,
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.transport,
    note:
      hv.ran && !hv.accepted && hv.errorCode !== MCP_ERROR_CODES.headerMismatch
        ? `Rejected, but not with HeaderMismatch (${MCP_ERROR_CODES.headerMismatch}). The spec requires 400 Bad Request with that code so intermediaries can distinguish it from other failures.`
        : hv.accepted
          ? 'Mcp-Method/Mcp-Name mirror body fields so gateways can route without parsing the body. A server that does not validate them lets an intermediary be routed one way while the server executes another.'
          : undefined,
  });

  const sessionMinted = !!conn.sessionId;
  const getStatus = probes.getMethod.status;
  const getRejected = !probes.getMethod.ran || getStatus === 405 || getStatus === 404 || getStatus === 0;
  results.push({
    passed: !sessionMinted && getRejected,
    ruleId: 'stateless-transport',
    message: sessionMinted
      ? `FAILED: Server minted an Mcp-Session-Id ("${conn.sessionId}"); protocol-level sessions were removed in 2026-07-28.`
      : !getRejected
        ? `FAILED: GET on the MCP endpoint returned ${getStatus}; the standalone SSE endpoint was replaced by subscriptions/listen and GET should return 405.`
        : 'Transport is stateless (no session ID minted, GET not served)',
    severity: 'warning',
    docUrl: MCP_SPEC_URLS.transport,
    note:
      sessionMinted || !getRejected
        ? 'State that spans requests must be referenced by an explicit identifier passed as an ordinary parameter, not inferred from the connection.'
        : undefined,
  });

  results.push(deprecatedFeatureRule(conn));

  results.push({
    passed: auth.passed,
    ruleId: 'authentication',
    message: auth.message,
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.authorization,
    note: auth.note,
  });

  return results;
}

// ─── Legacy (handshake-era) rules ────────────────────────────────────────────

function legacyRules(conn: MCPConnection, probes: ProbeResults, auth: AuthOutcome): RuleResult[] {
  const results: RuleResult[] = [];

  results.push({
    passed: false,
    ruleId: 'protocol-era',
    message: `Server is handshake-based (initialize/${conn.protocolVersion}); the current revision ${MCP_LATEST_VERSION} is stateless.`,
    severity: 'warning',
    docUrl: MCP_SPEC_URLS.versioning,
    note: `MCP ${MCP_LATEST_VERSION} removed the initialize/notifications/initialized handshake and the Mcp-Session-Id header. Every request now carries its protocol version, client identity and capabilities in params._meta, and servers must implement server/discover. Supporting both eras on the same endpoint ("dual-era") is allowed while clients migrate.`,
  });

  results.push(versionRule(conn));

  const hasIdentity = !!(conn.serverInfo?.name && conn.serverInfo?.version);
  results.push({
    passed: hasIdentity,
    ruleId: 'server-info',
    message: hasIdentity
      ? `Server info present: "${conn.serverInfo?.name}" v${conn.serverInfo?.version}`
      : 'MISSING: Server must return "serverInfo" with "name" and "version".',
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.basic,
  });

  results.push(...capabilityRules(conn));

  results.push({
    passed: !!conn.initialize?.serverInfo,
    ruleId: 'initialize-method',
    message: conn.initialize?.serverInfo
      ? 'Initialize request handled correctly'
      : 'FAILED: Server did not handle the "initialize" JSON-RPC request.',
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.versioning,
  });

  results.push({
    passed: conn.probe.discoverImplemented,
    ruleId: 'server-discover',
    message: conn.probe.discoverImplemented
      ? 'server/discover implemented alongside the handshake (dual-era server)'
      : 'Not implemented: server/discover is required by 2026-07-28 and is how modern clients detect this server.',
    severity: 'warning',
    docUrl: MCP_SPEC_URLS.discover,
  });

  results.push({
    passed: probes.ping.ok,
    ruleId: 'ping-method',
    message: probes.ping.ran ? probes.ping.message : 'Ping not tested',
    severity: 'info',
    note: 'ping was removed in 2026-07-28 — a stateless server has no handshake to keep alive. It remains valid on handshake-era revisions.',
  });

  results.push({
    passed: probes.toolsList.ok,
    ruleId: 'tools-list',
    message: probes.toolsList.ok
      ? `tools/list returned ${probes.toolsList.result?.tools?.length ?? 0} tool(s)`
      : 'tools/list did not return a result (server may not expose tools)',
    severity: 'info',
  });

  results.push(deprecatedFeatureRule(conn));

  results.push({
    passed: auth.passed,
    ruleId: 'authentication',
    message: auth.message,
    severity: 'critical',
    docUrl: MCP_SPEC_URLS.authorization,
    note: auth.note,
  });

  return results;
}
