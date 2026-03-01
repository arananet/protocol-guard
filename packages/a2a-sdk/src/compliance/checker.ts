import type {
  A2AAgentCard,
  ComplianceRule,
  ComplianceResult,
  ComplianceReport,
} from '../types';

export const A2A_COMPLIANCE_RULES: ComplianceRule[] = [
  {
    id: 'agent-card-name',
    name: 'Agent Name',
    description: 'Agent card must have a name',
    severity: 'critical',
    check: (agentCard) => ({
      passed: !!agentCard.name,
      ruleId: 'agent-card-name',
      message: agentCard.name ? 'Agent name present' : 'Missing agent name',
      severity: 'critical' as const,
    }),
  },
  {
    id: 'agent-card-description',
    name: 'Agent Description',
    description: 'Agent card must have a description',
    severity: 'critical',
    check: (agentCard) => ({
      passed: !!agentCard.description,
      ruleId: 'agent-card-description',
      message: agentCard.description ? 'Agent description present' : 'Missing agent description',
      severity: 'critical' as const,
    }),
  },
  {
    id: 'agent-card-url',
    name: 'Agent URL',
    description: 'Agent card must have a valid URL',
    severity: 'critical',
    check: (agentCard) => {
      const hasUrl = !!agentCard.url;
      const isValidUrl = hasUrl ? isValidURL(agentCard.url) : false;
      return {
        passed: isValidUrl,
        ruleId: 'agent-card-url',
        message: isValidUrl ? 'Agent URL valid' : 'Missing or invalid agent URL',
        severity: 'critical' as const,
      };
    },
  },
  {
    id: 'agent-card-version',
    name: 'Version',
    description: 'Agent card must have a version string',
    severity: 'critical',
    check: (agentCard) => ({
      passed: !!agentCard.version,
      ruleId: 'agent-card-version',
      message: agentCard.version ? 'Version present' : 'Missing version',
      severity: 'critical' as const,
    }),
  },
  {
    id: 'agent-card-capabilities',
    name: 'Capabilities',
    description: 'Agent card must declare capabilities',
    severity: 'warning',
    check: (agentCard) => ({
      passed: !!agentCard.capabilities,
      ruleId: 'agent-card-capabilities',
      message: agentCard.capabilities ? 'Capabilities declared' : 'No capabilities declared',
      severity: 'warning' as const,
    }),
  },
  {
    id: 'agent-card-streaming',
    name: 'Streaming Capability',
    description: 'If streaming is supported, it should be explicitly declared',
    severity: 'info',
    check: (agentCard) => {
      const caps = agentCard.capabilities;
      const hasStreaming = caps?.streaming !== undefined;
      return {
        passed: true,
        ruleId: 'agent-card-streaming',
        message: hasStreaming 
          ? `Streaming: ${caps.streaming ? 'supported' : 'not supported'}`
          : 'Streaming not declared',
        severity: 'info' as const,
      };
    },
  },
  {
    id: 'agent-card-push-notifications',
    name: 'Push Notifications',
    description: 'If push notifications are supported, it should be declared',
    severity: 'info',
    check: (agentCard) => {
      const caps = agentCard.capabilities;
      const hasPush = caps?.pushNotifications !== undefined;
      return {
        passed: true,
        ruleId: 'agent-card-push-notifications',
        message: hasPush
          ? `Push notifications: ${caps.pushNotifications ? 'supported' : 'not supported'}`
          : 'Push notifications not declared',
        severity: 'info' as const,
      };
    },
  },
  {
    id: 'agent-card-authentication',
    name: 'Authentication',
    description: 'Agent card must declare supported authentication schemes',
    severity: 'critical',
    check: (agentCard) => {
      const hasAuth = agentCard.authentication?.schemes?.length > 0;
      return {
        passed: hasAuth,
        ruleId: 'agent-card-authentication',
        message: hasAuth
          ? `Authentication schemes: ${agentCard.authentication.schemes.join(', ')}`
          : 'No authentication schemes declared',
        severity: 'critical' as const,
      };
    },
  },
  {
    id: 'agent-card-provider',
    name: 'Provider Information',
    description: 'Provider information should be included for enterprise use',
    severity: 'info',
    check: (agentCard) => ({
      passed: true,
      ruleId: 'agent-card-provider',
      message: agentCard.provider
        ? `Provider: ${agentCard.provider.organization}`
        : 'Provider not specified',
      severity: 'info' as const,
    }),
  },
  {
    id: 'agent-card-models',
    name: 'Supported Models',
    description: 'List of supported models should be included',
    severity: 'info',
    check: (agentCard) => ({
      passed: true,
      ruleId: 'agent-card-models',
      message: agentCard.supportedModels?.length
        ? `Supported models: ${agentCard.supportedModels.join(', ')}`
        : 'No models specified',
      severity: 'info' as const,
    }),
  },
];

function isValidURL(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export async function checkA2ACompliance(
  agentCard: A2AAgentCard,
  agentId: string
): Promise<ComplianceReport> {
  const results: ComplianceResult[] = [];

  for (const rule of A2A_COMPLIANCE_RULES) {
    try {
      const result = rule.check(agentCard);
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
    agentId,
    agentName: agentCard.name,
    agentCardUrl: agentCard.url,
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
