import type {
  UCPBusinessProfile,
  ComplianceRule,
  ComplianceResult,
  ComplianceReport,
} from '../types.js';

const SPEC_BASE = 'https://ucp.dev/latest/specification/overview';
const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
// Reverse-domain: at least 3 segments, all lowercase alphanumeric + hyphens
const NAMESPACE_REGEX = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2,}$/;

export const UCP_COMPLIANCE_RULES: ComplianceRule[] = [
  // ── Profile-level checks ──────────────────────────────────────────────
  {
    id: 'ucp-profile-root',
    name: 'Profile Root Object',
    description: 'Business profile must contain a top-level "ucp" object',
    severity: 'critical',
    specRef: `${SPEC_BASE}#business-profile`,
    check: (profile) => ({
      passed: !!profile.ucp && typeof profile.ucp === 'object',
      ruleId: 'ucp-profile-root',
      message: profile.ucp ? 'Top-level "ucp" object present' : 'Missing top-level "ucp" object',
      severity: 'critical',
      docUrl: `${SPEC_BASE}#business-profile`,
    }),
  },
  {
    id: 'ucp-version',
    name: 'UCP Version',
    description: 'ucp.version must exist and follow YYYY-MM-DD format',
    severity: 'critical',
    specRef: `${SPEC_BASE}#versioning`,
    check: (profile) => {
      const v = profile.ucp?.version;
      const valid = !!v && DATE_REGEX.test(v);
      return {
        passed: valid,
        ruleId: 'ucp-version',
        message: valid
          ? `UCP version: ${v}`
          : v
            ? `Invalid version format "${v}" — expected YYYY-MM-DD`
            : 'Missing ucp.version',
        severity: 'critical',
        details: { version: v },
        docUrl: `${SPEC_BASE}#versioning`,
      };
    },
  },

  // ── Services checks ───────────────────────────────────────────────────
  {
    id: 'ucp-services-present',
    name: 'Services Object',
    description: 'ucp.services must be a non-empty object',
    severity: 'critical',
    specRef: `${SPEC_BASE}#services`,
    check: (profile) => {
      const svc = profile.ucp?.services;
      const hasServices = !!svc && typeof svc === 'object' && Object.keys(svc).length > 0;
      return {
        passed: hasServices,
        ruleId: 'ucp-services-present',
        message: hasServices
          ? `${Object.keys(svc!).length} service(s) declared`
          : 'Missing or empty ucp.services object',
        severity: 'critical',
        docUrl: `${SPEC_BASE}#services`,
      };
    },
  },
  {
    id: 'ucp-service-namespace',
    name: 'Service Namespace',
    description: 'Service keys must follow reverse-domain notation (e.g. dev.ucp.shopping)',
    severity: 'critical',
    specRef: `${SPEC_BASE}#namespace-governance`,
    check: (profile) => {
      const keys = Object.keys(profile.ucp?.services || {});
      const invalid = keys.filter(k => !NAMESPACE_REGEX.test(k));
      return {
        passed: invalid.length === 0 && keys.length > 0,
        ruleId: 'ucp-service-namespace',
        message: invalid.length === 0
          ? 'All service keys follow reverse-domain notation'
          : `Invalid service namespace(s): ${invalid.join(', ')}`,
        severity: 'critical',
        details: { invalidKeys: invalid },
        docUrl: `${SPEC_BASE}#namespace-governance`,
      };
    },
  },
  {
    id: 'ucp-service-version',
    name: 'Service Versions',
    description: 'Each service must have a version in YYYY-MM-DD format',
    severity: 'critical',
    specRef: `${SPEC_BASE}#services`,
    check: (profile) => {
      const services = profile.ucp?.services || {};
      const entries = Object.entries(services);
      const invalid = entries.filter(([, s]) => !s?.version || !DATE_REGEX.test(s.version));
      return {
        passed: invalid.length === 0 && entries.length > 0,
        ruleId: 'ucp-service-version',
        message: invalid.length === 0
          ? 'All services have valid YYYY-MM-DD versions'
          : `${invalid.length} service(s) missing valid version`,
        severity: 'critical',
        details: { invalid: invalid.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#services`,
      };
    },
  },
  {
    id: 'ucp-service-spec',
    name: 'Service Spec URLs',
    description: 'Each service must have a spec URL pointing to its canonical specification',
    severity: 'critical',
    specRef: `${SPEC_BASE}#services`,
    check: (profile) => {
      const services = profile.ucp?.services || {};
      const entries = Object.entries(services);
      const missing = entries.filter(([, s]) => !s?.spec);
      return {
        passed: missing.length === 0 && entries.length > 0,
        ruleId: 'ucp-service-spec',
        message: missing.length === 0
          ? 'All services have spec URLs'
          : `${missing.length} service(s) missing spec URL`,
        severity: 'critical',
        details: { missing: missing.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#services`,
      };
    },
  },
  {
    id: 'ucp-service-transport',
    name: 'Transport Bindings',
    description: 'Each service must declare at least one transport (rest, mcp, a2a, or embedded)',
    severity: 'critical',
    specRef: `${SPEC_BASE}#transport-layer`,
    check: (profile) => {
      const services = profile.ucp?.services || {};
      const entries = Object.entries(services);
      const missing = entries.filter(([, s]) => {
        const t = s?.transport;
        if (!t || typeof t !== 'object') return true;
        return !(t.rest || t.mcp || t.a2a || t.embedded);
      });
      const transports = entries.map(([name, s]) => ({
        name,
        rest: !!s?.transport?.rest,
        mcp: !!s?.transport?.mcp,
        a2a: !!s?.transport?.a2a,
        embedded: !!s?.transport?.embedded,
      }));
      return {
        passed: missing.length === 0 && entries.length > 0,
        ruleId: 'ucp-service-transport',
        message: missing.length === 0
          ? 'All services have transport bindings'
          : `${missing.length} service(s) missing transport bindings`,
        severity: 'critical',
        details: { transports },
        docUrl: `${SPEC_BASE}#transport-layer`,
      };
    },
  },
  {
    id: 'ucp-transport-endpoints-https',
    name: 'HTTPS Endpoints',
    description: 'All transport endpoints must use HTTPS',
    severity: 'critical',
    specRef: `${SPEC_BASE}#security`,
    check: (profile) => {
      const services = profile.ucp?.services || {};
      const insecure: string[] = [];
      for (const [name, svc] of Object.entries(services)) {
        const t = svc?.transport;
        if (!t) continue;
        if (t.rest?.endpoint && !t.rest.endpoint.startsWith('https://')) insecure.push(`${name} REST`);
        if (t.mcp?.endpoint && !t.mcp.endpoint.startsWith('https://')) insecure.push(`${name} MCP`);
        if (t.a2a?.endpoint && !t.a2a.endpoint.startsWith('https://')) insecure.push(`${name} A2A`);
      }
      return {
        passed: insecure.length === 0,
        ruleId: 'ucp-transport-endpoints-https',
        message: insecure.length === 0
          ? 'All transport endpoints use HTTPS'
          : `Non-HTTPS endpoints: ${insecure.join(', ')}`,
        severity: 'critical',
        details: { insecure },
        docUrl: `${SPEC_BASE}#security`,
      };
    },
  },

  // ── Capabilities checks ───────────────────────────────────────────────
  {
    id: 'ucp-capabilities-present',
    name: 'Capabilities Object',
    description: 'ucp.capabilities must be a non-empty object',
    severity: 'critical',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const caps = profile.ucp?.capabilities;
      const hasCaps = !!caps && typeof caps === 'object' && Object.keys(caps).length > 0;
      return {
        passed: hasCaps,
        ruleId: 'ucp-capabilities-present',
        message: hasCaps
          ? `${Object.keys(caps!).length} capability(ies) declared`
          : 'Missing or empty ucp.capabilities object',
        severity: 'critical',
        details: { count: caps ? Object.keys(caps).length : 0 },
        docUrl: `${SPEC_BASE}#capabilities`,
      };
    },
  },
  {
    id: 'ucp-capability-namespace',
    name: 'Capability Namespace',
    description: 'Capability keys must follow reverse-domain notation (e.g. dev.ucp.shopping.checkout)',
    severity: 'critical',
    specRef: `${SPEC_BASE}#namespace-governance`,
    check: (profile) => {
      const keys = Object.keys(profile.ucp?.capabilities || {});
      const invalid = keys.filter(k => !NAMESPACE_REGEX.test(k));
      return {
        passed: invalid.length === 0 && keys.length > 0,
        ruleId: 'ucp-capability-namespace',
        message: invalid.length === 0
          ? 'All capability keys follow reverse-domain notation'
          : `Invalid capability namespace(s): ${invalid.join(', ')}`,
        severity: 'critical',
        details: { invalidKeys: invalid },
        docUrl: `${SPEC_BASE}#namespace-governance`,
      };
    },
  },
  {
    id: 'ucp-capability-version',
    name: 'Capability Versions',
    description: 'Each capability must have a version in YYYY-MM-DD format',
    severity: 'critical',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const caps = profile.ucp?.capabilities || {};
      const entries = Object.entries(caps);
      const invalid = entries.filter(([, c]) => !c?.version || !DATE_REGEX.test(c.version));
      return {
        passed: invalid.length === 0 && entries.length > 0,
        ruleId: 'ucp-capability-version',
        message: invalid.length === 0
          ? 'All capabilities have valid YYYY-MM-DD versions'
          : `${invalid.length} capability(ies) missing valid version`,
        severity: 'critical',
        details: { invalid: invalid.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#capabilities`,
      };
    },
  },
  {
    id: 'ucp-capability-spec',
    name: 'Capability Spec URLs',
    description: 'Each capability must have a spec URL',
    severity: 'critical',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const caps = profile.ucp?.capabilities || {};
      const entries = Object.entries(caps);
      const missing = entries.filter(([, c]) => !c?.spec);
      return {
        passed: missing.length === 0 && entries.length > 0,
        ruleId: 'ucp-capability-spec',
        message: missing.length === 0
          ? 'All capabilities have spec URLs'
          : `${missing.length} capability(ies) missing spec URL`,
        severity: 'critical',
        details: { missing: missing.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#capabilities`,
      };
    },
  },
  {
    id: 'ucp-capability-schema',
    name: 'Capability Schema URLs',
    description: 'Each capability must have a JSON Schema URL',
    severity: 'critical',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const caps = profile.ucp?.capabilities || {};
      const entries = Object.entries(caps);
      const missing = entries.filter(([, c]) => !c?.schema);
      return {
        passed: missing.length === 0 && entries.length > 0,
        ruleId: 'ucp-capability-schema',
        message: missing.length === 0
          ? 'All capabilities have schema URLs'
          : `${missing.length} capability(ies) missing schema URL`,
        severity: 'critical',
        details: { missing: missing.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#capabilities`,
      };
    },
  },
  {
    id: 'ucp-capability-extends',
    name: 'Extension Validity',
    description: 'Capabilities with "extends" must reference an existing parent capability',
    severity: 'warning',
    specRef: `${SPEC_BASE}#extensions`,
    check: (profile) => {
      const caps = profile.ucp?.capabilities || {};
      const capKeys = new Set(Object.keys(caps));
      const extensions = Object.entries(caps).filter(([, c]) => c?.extends);
      const orphans = extensions.filter(([, c]) => !capKeys.has(c.extends!));
      if (extensions.length === 0) {
        return {
          passed: true,
          ruleId: 'ucp-capability-extends',
          message: 'No extensions declared',
          severity: 'warning',
        };
      }
      return {
        passed: orphans.length === 0,
        ruleId: 'ucp-capability-extends',
        message: orphans.length === 0
          ? `${extensions.length} extension(s) all reference valid parents`
          : `Orphan extensions: ${orphans.map(([k]) => k).join(', ')}`,
        severity: 'warning',
        details: { orphans: orphans.map(([k, c]) => ({ key: k, extends: c.extends })) },
        docUrl: `${SPEC_BASE}#extensions`,
      };
    },
  },

  // ── Spec-binding check ────────────────────────────────────────────────
  {
    id: 'ucp-spec-binding',
    name: 'Spec URL Binding',
    description: 'Service/capability spec URL origin should match the namespace authority',
    severity: 'warning',
    specRef: `${SPEC_BASE}#namespace-governance`,
    check: (profile) => {
      const mismatches: string[] = [];
      // Check services
      for (const [key, svc] of Object.entries(profile.ucp?.services || {})) {
        if (svc?.spec) {
          try {
            const specHost = new URL(svc.spec).hostname;
            // e.g. "dev.ucp.shopping" → authority is "ucp.dev"
            const parts = key.split('.');
            const authority = parts.length >= 2 ? `${parts[1]}.${parts[0]}` : '';
            if (authority && !specHost.endsWith(authority)) {
              mismatches.push(`${key} → ${specHost}`);
            }
          } catch { /* skip invalid URLs */ }
        }
      }
      return {
        passed: mismatches.length === 0,
        ruleId: 'ucp-spec-binding',
        message: mismatches.length === 0
          ? 'All spec URLs match their namespace authority'
          : `Mismatched spec bindings: ${mismatches.join('; ')}`,
        severity: 'warning',
        details: { mismatches },
        docUrl: `${SPEC_BASE}#namespace-governance`,
      };
    },
  },

  // ── Payment handlers ──────────────────────────────────────────────────
  {
    id: 'ucp-payment-handlers',
    name: 'Payment Handlers',
    description: 'If payment_handlers is present, each handler must have version, spec, and schema',
    severity: 'warning',
    specRef: `${SPEC_BASE}#payment-architecture`,
    check: (profile) => {
      const handlers = profile.ucp?.payment_handlers;
      if (!handlers || Object.keys(handlers).length === 0) {
        return {
          passed: true,
          ruleId: 'ucp-payment-handlers',
          message: 'No payment handlers declared (optional)',
          severity: 'warning',
        };
      }
      const entries = Object.entries(handlers);
      const invalid = entries.filter(([, h]) => !h?.version || !h?.spec || !h?.schema);
      return {
        passed: invalid.length === 0,
        ruleId: 'ucp-payment-handlers',
        message: invalid.length === 0
          ? `${entries.length} payment handler(s) fully specified`
          : `${invalid.length} payment handler(s) missing required fields (version, spec, schema)`,
        severity: 'warning',
        details: { invalid: invalid.map(([k]) => k), total: entries.length },
        docUrl: `${SPEC_BASE}#payment-architecture`,
      };
    },
  },

  // ── Signing keys ──────────────────────────────────────────────────────
  {
    id: 'ucp-signing-keys',
    name: 'Signing Keys',
    description: 'If signing_keys is present, each key must have kty field (JWK format)',
    severity: 'info',
    specRef: `${SPEC_BASE}#security`,
    check: (profile) => {
      const keys = profile.signing_keys;
      if (!keys || keys.length === 0) {
        return {
          passed: true,
          ruleId: 'ucp-signing-keys',
          message: 'No signing keys declared (optional, used for webhook verification)',
          severity: 'info',
        };
      }
      const invalid = keys.filter(k => !k.kty);
      return {
        passed: invalid.length === 0,
        ruleId: 'ucp-signing-keys',
        message: invalid.length === 0
          ? `${keys.length} signing key(s) in valid JWK format`
          : `${invalid.length} signing key(s) missing kty field`,
        severity: 'info',
        details: { count: keys.length, invalid: invalid.length },
        docUrl: `${SPEC_BASE}#security`,
      };
    },
  },

  // ── Namespace governance ──────────────────────────────────────────────
  {
    id: 'ucp-vendor-namespace',
    name: 'Vendor Namespace',
    description: 'Custom capabilities should use vendor namespace (com.{vendor}.*) not dev.ucp.*',
    severity: 'info',
    specRef: `${SPEC_BASE}#namespace-governance`,
    check: (profile) => {
      const caps = Object.keys(profile.ucp?.capabilities || {});
      const standard = caps.filter(k => k.startsWith('dev.ucp.'));
      const vendor = caps.filter(k => !k.startsWith('dev.ucp.'));
      return {
        passed: true,
        ruleId: 'ucp-vendor-namespace',
        message: vendor.length > 0
          ? `${vendor.length} vendor capability(ies), ${standard.length} standard (dev.ucp.*)`
          : `All ${standard.length} capability(ies) use standard dev.ucp.* namespace`,
        severity: 'info',
        details: { standard: standard.length, vendor: vendor.length },
        docUrl: `${SPEC_BASE}#namespace-governance`,
      };
    },
  },
];

export async function checkUCPCompliance(
  profile: UCPBusinessProfile,
  baseUrl: string
): Promise<ComplianceReport> {
  const results: ComplianceResult[] = [];

  for (const rule of UCP_COMPLIANCE_RULES) {
    try {
      const result = rule.check(profile);
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
    baseUrl,
    specVersion: profile.ucp?.version || 'unknown',
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
