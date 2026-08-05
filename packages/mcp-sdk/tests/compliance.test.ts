import { describe, it, expect } from 'vitest';
import {
  MCP_COMPLIANCE_RULES,
  checkMCPCompliance,
  rulesForEra,
} from '../src/compliance/checker.js';
import { MCP_LATEST_VERSION } from '../src/types.js';
import type { MCPComplianceContext, MCPServerConfig } from '../src/types.js';

const server: MCPServerConfig = {
  id: 'test',
  name: 'test-server',
  url: 'https://example.test/mcp',
  auth: { type: 'none' },
};

function modernContext(overrides: Partial<MCPComplianceContext> = {}): MCPComplianceContext {
  return {
    era: 'modern',
    protocolVersion: MCP_LATEST_VERSION,
    supportedVersions: [MCP_LATEST_VERSION],
    serverInfo: { name: 'demo', version: '1.0.0' },
    capabilities: { tools: {} },
    discover: {
      resultType: 'complete',
      supportedVersions: [MCP_LATEST_VERSION],
      capabilities: { tools: {} },
      ttlMs: 3600000,
      cacheScope: 'public',
    },
    discoverImplemented: true,
    toolsResult: { resultType: 'complete', tools: [], ttlMs: 300000, cacheScope: 'public' },
    sessionId: null,
    ...overrides,
  };
}

function legacyContext(overrides: Partial<MCPComplianceContext> = {}): MCPComplianceContext {
  return {
    era: 'legacy',
    protocolVersion: '2025-06-18',
    serverInfo: { name: 'old', version: '0.9.0' },
    capabilities: { tools: {} },
    initialize: {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {} },
      serverInfo: { name: 'old', version: '0.9.0' },
    },
    discoverImplemented: false,
    sessionId: 'sess-1',
    ...overrides,
  };
}

function resultFor(report: Awaited<ReturnType<typeof checkMCPCompliance>>, ruleId: string) {
  return report.results.find((r) => r.ruleId === ruleId);
}

describe('rule selection by era', () => {
  it('applies stateless-only rules to modern servers', () => {
    const ids = rulesForEra('modern').map((r) => r.id);
    expect(ids).toContain('server-discover');
    expect(ids).toContain('result-type');
    expect(ids).toContain('cacheable-results');
    expect(ids).toContain('stateless-transport');
    expect(ids).not.toContain('initialize-method');
  });

  it('applies handshake-only rules to legacy servers', () => {
    const ids = rulesForEra('legacy').map((r) => r.id);
    expect(ids).toContain('initialize-method');
    expect(ids).toContain('notifications-initialized');
    expect(ids).not.toContain('server-discover');
    expect(ids).not.toContain('result-type');
  });

  it('shares the era-independent rules', () => {
    for (const id of ['protocol-version', 'server-info', 'deprecated-features']) {
      expect(rulesForEra('modern').map((r) => r.id)).toContain(id);
      expect(rulesForEra('legacy').map((r) => r.id)).toContain(id);
    }
  });

  it('gives every rule a check function', () => {
    for (const rule of MCP_COMPLIANCE_RULES) {
      expect(typeof rule.check).toBe('function');
    }
  });
});

describe('a fully conforming stateless server', () => {
  it('passes every critical rule', async () => {
    const report = await checkMCPCompliance(server, modernContext());

    expect(report.era).toBe('modern');
    expect(report.protocolVersion).toBe(MCP_LATEST_VERSION);
    expect(report.failedCount).toBe(0);
    expect(report.warningCount).toBe(0);
    expect(resultFor(report, 'protocol-era')?.passed).toBe(true);
  });
});

describe('protocol version grading', () => {
  it('fails a deprecated revision', async () => {
    const report = await checkMCPCompliance(
      server,
      legacyContext({ protocolVersion: '2025-03-26' })
    );
    const result = resultFor(report, 'protocol-version');

    expect(result?.passed).toBe(false);
    expect(result?.message).toMatch(/deprecated/i);
  });

  it('fails an unrecognized revision', async () => {
    const report = await checkMCPCompliance(
      server,
      modernContext({ protocolVersion: '1999-01-01' })
    );

    expect(resultFor(report, 'protocol-version')?.passed).toBe(false);
  });

  it('passes but flags a superseded revision', async () => {
    const report = await checkMCPCompliance(server, legacyContext());
    const result = resultFor(report, 'protocol-version');

    expect(result?.passed).toBe(true);
    expect(result?.message).toMatch(/superseded/);
  });

  it('flags the handshake era itself', async () => {
    const report = await checkMCPCompliance(server, legacyContext());

    expect(resultFor(report, 'protocol-era')?.passed).toBe(false);
    expect(report.warningCount).toBeGreaterThan(0);
  });
});

describe('stateless-era rules', () => {
  it('fails when server/discover is missing', async () => {
    const report = await checkMCPCompliance(
      server,
      modernContext({ discoverImplemented: false, discover: null })
    );

    expect(resultFor(report, 'server-discover')?.passed).toBe(false);
  });

  it('fails when a result omits resultType', async () => {
    const report = await checkMCPCompliance(
      server,
      modernContext({ toolsResult: { tools: [], ttlMs: 1000, cacheScope: 'public' } })
    );

    expect(resultFor(report, 'result-type')?.passed).toBe(false);
  });

  it('fails when cache hints are missing or invalid', async () => {
    const missing = await checkMCPCompliance(
      server,
      modernContext({ toolsResult: { resultType: 'complete', tools: [] } })
    );
    expect(resultFor(missing, 'cacheable-results')?.passed).toBe(false);

    const negative = await checkMCPCompliance(
      server,
      modernContext({
        toolsResult: { resultType: 'complete', tools: [], ttlMs: -5, cacheScope: 'public' },
      })
    );
    expect(resultFor(negative, 'cacheable-results')?.passed).toBe(false);
  });

  it('fails when the server mints a session id', async () => {
    const report = await checkMCPCompliance(server, modernContext({ sessionId: 'sess-9' }));
    const result = resultFor(report, 'stateless-transport');

    expect(result?.passed).toBe(false);
    expect(result?.message).toMatch(/Mcp-Session-Id/);
  });

  it('fails when server identity is missing from the result _meta', async () => {
    const report = await checkMCPCompliance(server, modernContext({ serverInfo: null }));

    expect(resultFor(report, 'server-info')?.passed).toBe(false);
    expect(resultFor(report, 'server-info')?.message).toMatch(/serverInfo/);
  });
});

describe('deprecated features', () => {
  it('flags roots, sampling and logging capabilities', async () => {
    const report = await checkMCPCompliance(
      server,
      modernContext({ capabilities: { tools: {}, roots: {}, sampling: {}, logging: {} } })
    );
    const result = resultFor(report, 'deprecated-features');

    expect(result?.passed).toBe(false);
    expect(result?.message).toMatch(/roots/);
    expect(result?.message).toMatch(/sampling/);
    expect(result?.message).toMatch(/logging/);
  });

  it('passes a server that declares none of them', async () => {
    const report = await checkMCPCompliance(server, modernContext());
    expect(resultFor(report, 'deprecated-features')?.passed).toBe(true);
  });
});
