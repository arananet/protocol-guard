import {
  MCP_KNOWN_VERSIONS,
  MCP_LATEST_VERSION,
  MCP_LEGACY_VERSIONS,
} from '../types.js';
import type {
  MCPServerConfig,
  ComplianceRule,
  ComplianceResult,
  ComplianceReport,
  MCPComplianceContext,
} from '../types.js';

export { MCP_KNOWN_VERSIONS, MCP_LATEST_VERSION };

/** Revisions that predate the hardened OAuth Resource Server model. */
export const MCP_DEPRECATED_VERSIONS: Record<string, string> = {
  '2024-11-05': 'no standardized authorization framework',
  '2025-03-26': 'OAuth 2.1 without Resource Indicators (RFC 8707)',
};

/** Features that entered the Deprecated state in 2026-07-28. */
export const MCP_DEPRECATED_CAPABILITIES: Record<string, string> = {
  roots: 'pass directories or files via tool parameters, resource URIs, or server configuration',
  sampling: 'integrate directly with an LLM provider API',
  logging: 'log to stderr (stdio) or use OpenTelemetry',
};

/**
 * Compliance rules for both eras of MCP.
 *
 * Rules tagged `eras: ['modern']` grade a stateless 2026-07-28 server;
 * `eras: ['legacy']` rules grade a handshake-era server. Untagged rules apply to
 * both.
 */
export const MCP_COMPLIANCE_RULES: ComplianceRule[] = [
  {
    id: 'protocol-version',
    name: 'Protocol Version',
    description: 'Server must speak a published, non-deprecated protocol revision',
    severity: 'critical',
    check: (_server, ctx) => {
      const version = ctx.protocolVersion;
      if (!version) {
        return {
          passed: false,
          ruleId: 'protocol-version',
          message: 'Missing protocol version',
          severity: 'critical',
        };
      }

      const deprecation = MCP_DEPRECATED_VERSIONS[version];
      if (deprecation) {
        return {
          passed: false,
          ruleId: 'protocol-version',
          message: `Protocol version "${version}" is deprecated (${deprecation}). Upgrade to ${MCP_LATEST_VERSION}.`,
          severity: 'critical',
        };
      }

      if (!MCP_KNOWN_VERSIONS.includes(version)) {
        return {
          passed: false,
          ruleId: 'protocol-version',
          message: `Protocol version present but unrecognized: "${version}"`,
          severity: 'critical',
        };
      }

      const superseded = (MCP_LEGACY_VERSIONS as readonly string[]).includes(version);
      return {
        passed: true,
        ruleId: 'protocol-version',
        message: superseded
          ? `Protocol version present: ${version} (superseded by ${MCP_LATEST_VERSION})`
          : `Protocol version present: ${version}`,
        severity: 'critical',
      };
    },
  },
  {
    id: 'protocol-era',
    name: 'Protocol Era',
    description: `Server should implement the stateless model introduced in ${MCP_LATEST_VERSION}`,
    severity: 'warning',
    check: (_server, ctx) => ({
      passed: ctx.era === 'modern',
      ruleId: 'protocol-era',
      message:
        ctx.era === 'modern'
          ? 'Server implements the stateless protocol (per-request metadata)'
          : `Server is handshake-based (initialize / Mcp-Session-Id); ${MCP_LATEST_VERSION} is stateless`,
      severity: 'warning',
    }),
  },
  {
    id: 'server-discover',
    name: 'Server Discovery',
    description: 'Servers MUST implement server/discover',
    severity: 'critical',
    eras: ['modern'],
    check: (_server, ctx) => ({
      passed: ctx.discoverImplemented,
      ruleId: 'server-discover',
      message: ctx.discoverImplemented
        ? 'server/discover implemented'
        : 'server/discover not implemented — required to advertise supported versions, capabilities and identity',
      severity: 'critical',
    }),
  },
  {
    id: 'supported-versions',
    name: 'Supported Versions',
    description: 'server/discover must advertise supportedVersions',
    severity: 'warning',
    eras: ['modern'],
    check: (_server, ctx) => {
      const versions = ctx.supportedVersions;
      const has = Array.isArray(versions) && versions.length > 0;
      return {
        passed: has,
        ruleId: 'supported-versions',
        message: has
          ? `Server advertises: ${versions!.join(', ')}`
          : 'Missing supportedVersions in the server/discover result',
        severity: 'warning',
        details: has ? { supportedVersions: versions } : undefined,
      };
    },
  },
  {
    id: 'server-info',
    name: 'Server Info',
    description: 'Server must identify itself with a name and version',
    severity: 'critical',
    check: (_server, ctx) => {
      const info = ctx.serverInfo;
      const has = !!(info && info.name && info.version);
      return {
        passed: has,
        ruleId: 'server-info',
        message: has
          ? `Server info present: ${info!.name} v${info!.version}`
          : ctx.era === 'modern'
            ? 'Missing io.modelcontextprotocol/serverInfo in the result _meta'
            : 'Missing server info',
        severity: 'critical',
        details: info ?? undefined,
      };
    },
  },
  {
    id: 'capabilities-object',
    name: 'Capabilities Object',
    description: 'Server must return a capabilities object (even if empty)',
    severity: 'warning',
    check: (_server, ctx) => {
      const has = ctx.capabilities !== null && typeof ctx.capabilities === 'object';
      return {
        passed: has,
        ruleId: 'capabilities-object',
        message: has ? 'Capabilities object present' : 'Missing capabilities object',
        severity: 'warning',
      };
    },
  },
  {
    id: 'tools-capability',
    name: 'Tools Capability',
    description: 'If tools are supported, capabilities.tools must be present',
    severity: 'info',
    check: (_server, ctx) => ({
      passed: true,
      ruleId: 'tools-capability',
      message: ctx.capabilities?.tools !== undefined
        ? 'Tools capability declared'
        : 'Tools not declared',
      severity: 'info',
    }),
  },
  {
    id: 'resources-capability',
    name: 'Resources Capability',
    description: 'If resources are supported, capabilities.resources must be present',
    severity: 'info',
    check: (_server, ctx) => ({
      passed: true,
      ruleId: 'resources-capability',
      message: ctx.capabilities?.resources !== undefined
        ? 'Resources capability declared'
        : 'Resources not declared',
      severity: 'info',
    }),
  },
  {
    id: 'prompts-capability',
    name: 'Prompts Capability',
    description: 'If prompts are supported, capabilities.prompts must be present',
    severity: 'info',
    check: (_server, ctx) => ({
      passed: true,
      ruleId: 'prompts-capability',
      message: ctx.capabilities?.prompts !== undefined
        ? 'Prompts capability declared'
        : 'Prompts not declared',
      severity: 'info',
    }),
  },
  {
    id: 'result-type',
    name: 'Result Type',
    description: 'Every result must carry a resultType field',
    severity: 'critical',
    eras: ['modern'],
    check: (_server, ctx) => {
      const observed = [ctx.discover?.resultType, ctx.toolsResult?.resultType].filter(
        (t): t is string => typeof t === 'string'
      );
      const missing =
        (!!ctx.discover && !ctx.discover.resultType) ||
        (!!ctx.toolsResult && !ctx.toolsResult.resultType);

      return {
        passed: observed.length > 0 && !missing,
        ruleId: 'result-type',
        message: missing
          ? 'Results are missing the required "resultType" field'
          : observed.length > 0
            ? `Results carry resultType: ${[...new Set(observed)].join(', ')}`
            : 'No result observed to check "resultType"',
        severity: 'critical',
      };
    },
  },
  {
    id: 'cacheable-results',
    name: 'Cache Hints',
    description: 'List and read results must carry ttlMs and cacheScope',
    severity: 'warning',
    eras: ['modern'],
    check: (_server, ctx) => {
      const result = ctx.toolsResult;
      if (!result) {
        return {
          passed: true,
          ruleId: 'cacheable-results',
          message: 'tools/list not fetched — cache hints not checked',
          severity: 'warning',
        };
      }

      const valid =
        typeof result.ttlMs === 'number' &&
        result.ttlMs >= 0 &&
        (result.cacheScope === 'public' || result.cacheScope === 'private');

      return {
        passed: valid,
        ruleId: 'cacheable-results',
        message: valid
          ? `Cache hints present on tools/list (ttlMs: ${result.ttlMs}, cacheScope: ${result.cacheScope})`
          : `Missing or invalid cache hints on tools/list (ttlMs: ${
              result.ttlMs ?? 'absent'
            }, cacheScope: ${result.cacheScope ?? 'absent'})`,
        severity: 'warning',
      };
    },
  },
  {
    id: 'stateless-transport',
    name: 'Stateless Transport',
    description: 'Protocol-level sessions were removed; no Mcp-Session-Id may be minted',
    severity: 'warning',
    eras: ['modern'],
    check: (_server, ctx) => ({
      passed: !ctx.sessionId,
      ruleId: 'stateless-transport',
      message: ctx.sessionId
        ? `Server minted an Mcp-Session-Id ("${ctx.sessionId}"); sessions were removed in ${MCP_LATEST_VERSION}`
        : 'Transport is stateless (no session ID minted)',
      severity: 'warning',
    }),
  },
  {
    id: 'deprecated-features',
    name: 'Deprecated Features',
    description: 'Roots, Sampling and Logging are deprecated as of 2026-07-28',
    severity: 'info',
    check: (_server, ctx) => {
      const caps = (ctx.capabilities || {}) as Record<string, unknown>;
      const declared = Object.keys(MCP_DEPRECATED_CAPABILITIES).filter(
        (name) => caps[name] !== undefined
      );
      return {
        passed: declared.length === 0,
        ruleId: 'deprecated-features',
        message:
          declared.length === 0
            ? 'No deprecated features declared'
            : `Deprecated capabilities declared: ${declared
                .map((d) => `${d} (${MCP_DEPRECATED_CAPABILITIES[d]})`)
                .join(', ')}`,
        severity: 'info',
      };
    },
  },
  {
    id: 'initialize-method',
    name: 'Initialize Method',
    description: 'Handshake-era servers must implement initialize',
    severity: 'critical',
    eras: ['legacy'],
    check: (_server, ctx) => {
      const has = !!ctx.initialize?.serverInfo;
      return {
        passed: has,
        ruleId: 'initialize-method',
        message: has ? 'Initialize method works' : 'Initialize method not implemented',
        severity: 'critical',
      };
    },
  },
  {
    id: 'notifications-initialized',
    name: 'Initialized Notification',
    description: 'Handshake-era servers must handle notifications/initialized',
    severity: 'warning',
    eras: ['legacy'],
    check: (_server, ctx) => {
      const has = !!ctx.initialize?.serverInfo;
      return {
        passed: has,
        ruleId: 'notifications-initialized',
        message: has
          ? 'Notification handler present'
          : 'Cannot verify notification handling',
        severity: 'warning',
      };
    },
  },
];

/** Rules that apply to a server in the given era. */
export function rulesForEra(era: MCPComplianceContext['era']): ComplianceRule[] {
  return MCP_COMPLIANCE_RULES.filter((rule) => !rule.eras || rule.eras.includes(era));
}

export async function checkMCPCompliance(
  server: MCPServerConfig,
  context: MCPComplianceContext
): Promise<ComplianceReport> {
  const results: ComplianceResult[] = [];

  for (const rule of rulesForEra(context.era)) {
    try {
      results.push(rule.check(server, context));
    } catch (error) {
      results.push({
        passed: false,
        ruleId: rule.id,
        message: `Rule check error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: rule.severity,
      });
    }
  }

  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.filter((r) => !r.passed && r.severity === 'critical').length;
  const warningCount = results.filter((r) => !r.passed && r.severity === 'warning').length;

  return {
    timestamp: new Date(),
    serverId: server.id || 'unknown',
    serverName: server.name,
    protocolVersion: context.protocolVersion || 'unknown',
    era: context.era,
    supportedVersions: context.supportedVersions,
    results,
    passedCount,
    failedCount,
    warningCount,
  };
}

export function getComplianceSummary(report: ComplianceReport): string {
  const total = report.results.length;
  const percentage = total === 0 ? 0 : Math.round((report.passedCount / total) * 100);

  let status = '✅ PASSED';
  if (report.failedCount > 0) status = '❌ FAILED';
  else if (report.warningCount > 0) status = '⚠️ WARNING';

  return `${status} - ${report.passedCount}/${total} (${percentage}%)`;
}
