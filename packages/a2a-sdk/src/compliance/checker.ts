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
    description: 'Agent card must expose at least one valid interface URL (or a legacy card url)',
    severity: 'critical',
    check: (agentCard) => {
      const urls = (agentCard.supportedInterfaces || []).map(i => i.url).filter(Boolean);
      if (agentCard.url) urls.push(agentCard.url);
      const valid = urls.filter(isValidURL);
      return {
        passed: valid.length > 0,
        ruleId: 'agent-card-url',
        message: valid.length > 0
          ? `${valid.length} valid interface URL(s)`
          : 'Missing or invalid agent URL',
        severity: 'critical' as const,
      };
    },
  },
  {
    id: 'agent-card-interfaces',
    name: 'Supported Interfaces (1.0)',
    description: 'A2A 1.0 cards declare supportedInterfaces, each with url, protocolBinding and protocolVersion',
    severity: 'warning',
    check: (agentCard) => {
      const interfaces = agentCard.supportedInterfaces || [];
      if (interfaces.length === 0) {
        return {
          passed: false,
          ruleId: 'agent-card-interfaces',
          message: agentCard.url
            ? 'No supportedInterfaces declared (pre-1.0 card shape with a single url)'
            : 'No supportedInterfaces declared',
          severity: 'warning' as const,
        };
      }
      const incomplete = interfaces.filter(i => !i.url || !i.protocolBinding || !i.protocolVersion);
      return {
        passed: incomplete.length === 0,
        ruleId: 'agent-card-interfaces',
        message: incomplete.length === 0
          ? `${interfaces.length} interface(s): ${interfaces.map(i => `${i.protocolBinding}@${i.protocolVersion}`).join(', ')}`
          : `${incomplete.length} interface(s) missing url, protocolBinding or protocolVersion`,
        severity: 'warning' as const,
        details: { count: interfaces.length, incomplete: incomplete.length },
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
    id: 'agent-card-protocol-version',
    name: 'Protocol Version',
    description: 'In A2A 1.0 each interface declares its protocolVersion; a card-level protocolVersion is the pre-1.0 location',
    severity: 'warning',
    check: (agentCard) => {
      const ifaceVersions = (agentCard.supportedInterfaces || [])
        .map(i => i.protocolVersion)
        .filter(Boolean) as string[];
      if (ifaceVersions.length > 0) {
        const current = ifaceVersions.filter(v => v === '1.0' || v.startsWith('1.'));
        return {
          passed: true,
          ruleId: 'agent-card-protocol-version',
          message: `Interface protocol version(s): ${[...new Set(ifaceVersions)].join(', ')}${current.length === 0 ? ' (no 1.x interface)' : ''}`,
          severity: 'warning' as const,
          details: { versions: ifaceVersions },
        };
      }
      return {
        passed: !!agentCard.protocolVersion,
        ruleId: 'agent-card-protocol-version',
        message: agentCard.protocolVersion
          ? `Protocol version (card-level, pre-1.0 location): ${agentCard.protocolVersion}`
          : 'No protocolVersion declared on card or interfaces',
        severity: 'warning' as const,
      };
    },
  },
  {
    id: 'agent-card-authentication',
    name: 'Security Schemes',
    description: 'Agent card must declare security schemes (securitySchemes/securityRequirements) or legacy authentication',
    severity: 'critical',
    check: (agentCard) => {
      const hasModern =
        (!!agentCard.securitySchemes && Object.keys(agentCard.securitySchemes).length > 0) ||
        (Array.isArray(agentCard.securityRequirements) && agentCard.securityRequirements.length > 0) ||
        (Array.isArray(agentCard.security) && agentCard.security.length > 0);
      const hasLegacy = !!agentCard.authentication?.schemes?.length;
      const hasAuth = hasModern || hasLegacy;
      let message: string;
      if (hasModern && agentCard.securitySchemes) {
        message = `Security schemes: ${Object.keys(agentCard.securitySchemes).join(', ')}`;
      } else if (hasModern) {
        message = 'Security requirement declared';
      } else if (hasLegacy) {
        message = `Legacy authentication schemes: ${agentCard.authentication!.schemes.join(', ')} (migrate to securitySchemes)`;
      } else {
        message = 'No security schemes declared';
      }
      return {
        passed: hasAuth,
        ruleId: 'agent-card-authentication',
        message,
        severity: 'critical' as const,
      };
    },
  },
  {
    id: 'agent-card-signature',
    name: 'Card Signature',
    description: 'Agent card should be JWS-signed for integrity (AgentCardSignature)',
    severity: 'info',
    check: (agentCard) => {
      const signed = Array.isArray(agentCard.signatures) && agentCard.signatures.length > 0;
      return {
        passed: true,
        ruleId: 'agent-card-signature',
        message: signed
          ? `Agent card is JWS-signed (${agentCard.signatures!.length} signature(s))`
          : 'Agent card is not signed: clients cannot verify integrity',
        severity: 'info' as const,
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
    agentCardUrl: agentCard.supportedInterfaces?.[0]?.url || agentCard.url || '',
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
