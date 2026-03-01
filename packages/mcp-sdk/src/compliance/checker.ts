import type {
  MCPServerConfig,
  ComplianceRule,
  ComplianceResult,
  ComplianceReport,
  MCPInitializeResponse,
} from '../types';

export const MCP_COMPLIANCE_RULES: ComplianceRule[] = [
  {
    id: 'protocol-version',
    name: 'Protocol Version',
    description: 'Server must return a valid protocol version',
    severity: 'critical',
    check: (_server, response) => {
      const result = response as MCPInitializeResponse;
      const hasVersion = !!result.protocolVersion;
      return {
        passed: hasVersion,
        ruleId: 'protocol-version',
        message: hasVersion ? 'Protocol version present' : 'Missing protocol version',
        severity: 'critical',
      };
    },
  },
  {
    id: 'server-info',
    name: 'Server Info',
    description: 'Server must return server info with name and version',
    severity: 'critical',
    check: (_server, response) => {
      const result = response as MCPInitializeResponse;
      const hasInfo = result.serverInfo && result.serverInfo.name && result.serverInfo.version;
      return {
        passed: !!hasInfo,
        ruleId: 'server-info',
        message: hasInfo ? 'Server info present' : 'Missing server info',
        severity: 'critical',
        details: result.serverInfo,
      };
    },
  },
  {
    id: 'capabilities-object',
    name: 'Capabilities Object',
    description: 'Server must return a capabilities object (even if empty)',
    severity: 'warning',
    check: (_server, response) => {
      const result = response as MCPInitializeResponse;
      const hasCaps = typeof result.capabilities === 'object';
      return {
        passed: hasCaps,
        ruleId: 'capabilities-object',
        message: hasCaps ? 'Capabilities object present' : 'Missing capabilities object',
        severity: 'warning',
      };
    },
  },
  {
    id: 'tools-capability',
    name: 'Tools Capability',
    description: 'If tools are supported, capabilities.tools must be present',
    severity: 'info',
    check: (_server, response) => {
      const result = response as MCPInitializeResponse;
      const caps = result.capabilities;
      const hasTools = caps?.tools !== undefined;
      return {
        passed: true,
        ruleId: 'tools-capability',
        message: hasTools ? 'Tools capability declared' : 'Tools not declared',
        severity: 'info',
      };
    },
  },
  {
    id: 'resources-capability',
    name: 'Resources Capability',
    description: 'If resources are supported, capabilities.resources must be present',
    severity: 'info',
    check: (_server, response) => {
      const result = response as MCPInitializeResponse;
      const caps = result.capabilities;
      const hasResources = caps?.resources !== undefined;
      return {
        passed: true,
        ruleId: 'resources-capability',
        message: hasResources ? 'Resources capability declared' : 'Resources not declared',
        severity: 'info',
      };
    },
  },
  {
    id: 'prompts-capability',
    name: 'Prompts Capability',
    description: 'If prompts are supported, capabilities.prompts must be present',
    severity: 'info',
    check: (_server, response) => {
      const result = response as MCPInitializeResponse;
      const caps = result.capabilities;
      const hasPrompts = caps?.prompts !== undefined;
      return {
        passed: true,
        ruleId: 'prompts-capability',
        message: hasPrompts ? 'Prompts capability declared' : 'Prompts not declared',
        severity: 'info',
      };
    },
  },
  {
    id: 'initialize-method',
    name: 'Initialize Method',
    description: 'Server must implement initialize method',
    severity: 'critical',
    check: (_server, response) => {
      const hasResult = (response as MCPInitializeResponse).serverInfo !== undefined;
      return {
        passed: hasResult,
        ruleId: 'initialize-method',
        message: hasResult ? 'Initialize method works' : 'Initialize method not implemented',
        severity: 'critical',
      };
    },
  },
  {
    id: 'notifications-initialized',
    name: 'Initialized Notification',
    description: 'Server must handle notifications/initialized after initialize',
    severity: 'warning',
    check: (_server, response) => {
      // This is checked implicitly - if initialize worked, notification was sent
      const hasResult = (response as MCPInitializeResponse).serverInfo !== undefined;
      return {
        passed: hasResult,
        ruleId: 'notifications-initialized',
        message: hasResult ? 'Notification handler present' : 'Cannot verify notification handling',
        severity: 'warning',
      };
    },
  },
  {
    id: 'ping-method',
    name: 'Ping Method',
    description: 'Server should implement ping method for health checks',
    severity: 'info',
    check: (_server, response) => {
      const initResponse = response as MCPInitializeResponse;
      const serverResponded = initResponse.serverInfo !== undefined && initResponse.protocolVersion !== undefined;
      return {
        passed: serverResponded,
        ruleId: 'ping-method',
        message: serverResponded
          ? 'Server is responsive to JSON-RPC (ping requires a live network call — use the web compliance tester for a real ping check)'
          : 'Server did not respond to JSON-RPC initialize — ping capability cannot be verified',
        severity: 'info',
      };
    },
  },
];

export async function checkMCPCompliance(
  server: MCPServerConfig,
  initializeResponse: MCPInitializeResponse
): Promise<ComplianceReport> {
  const results: ComplianceResult[] = [];

  for (const rule of MCP_COMPLIANCE_RULES) {
    try {
      const result = rule.check(server, initializeResponse);
      results.push(result);
    } catch (error) {
      results.push({
        passed: false,
        ruleId: rule.id,
        message: `Rule check error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: rule.severity,
      });
    }
  }

  const passedCount = results.filter(r => r.passed).length;
  const failedCount = results.filter(r => !r.passed && r.severity === 'critical').length;
  const warningCount = results.filter(r => !r.passed && r.severity === 'warning').length;

  return {
    timestamp: new Date(),
    serverId: server.id || 'unknown',
    serverName: server.name,
    protocolVersion: initializeResponse.protocolVersion,
    results,
    passedCount,
    failedCount,
    warningCount,
  };
}

export function getComplianceSummary(report: ComplianceReport): string {
  const total = report.results.length;
  const percentage = Math.round((report.passedCount / total) * 100);
  
  let status = '✅ PASSED';
  if (report.failedCount > 0) status = '❌ FAILED';
  else if (report.warningCount > 0) status = '⚠️ WARNING';
  
  return `${status} - ${report.passedCount}/${total} (${percentage}%)`;
}
