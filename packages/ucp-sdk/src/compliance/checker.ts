import type {
  UCPBusinessProfile,
  UCPRawProfile,
  ComplianceRule,
  ComplianceResult,
  ComplianceReport,
} from '../types.js';
import { UCP_CAPABILITIES, UCP_PAYMENT_CAPABILITY_NAMESPACE, UCP_SPEC_VERSION } from '../types.js';
import { normalizeUCPProfile } from '../client.js';

const SPEC_BASE = 'https://ucp.dev/2026-08-25/specification/overview';
const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
// Reverse-domain name pattern, taken verbatim from the normative schema
// common/types/reverse_domain_name.json of the 2026-08-25 spec (segments
// may contain underscores and may start with a digit after the first one).
const NAMESPACE_REGEX = /^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9_])?)+$/;
const VALID_TRANSPORTS = ['rest', 'mcp', 'a2a', 'embedded'];

function isAbsoluteUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

function allEntries<T>(record: Record<string, T[]> | undefined): Array<[string, T]> {
  const out: Array<[string, T]> = [];
  for (const [name, entries] of Object.entries(record || {})) {
    for (const entry of entries || []) out.push([name, entry]);
  }
  return out;
}

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
          ? v === UCP_SPEC_VERSION
            ? `UCP version: ${v} (current spec)`
            : `UCP version: ${v}`
          : v
            ? `Invalid version format "${v}", expected YYYY-MM-DD`
            : 'Missing ucp.version',
        severity: 'critical',
        details: { version: v, currentSpecVersion: UCP_SPEC_VERSION },
        docUrl: `${SPEC_BASE}#versioning`,
      };
    },
  },
  {
    id: 'ucp-supported-versions',
    name: 'Supported Versions (leaf profiles)',
    description: 'ucp.supported_versions, when present, must map YYYY-MM-DD versions to HTTPS profile URIs',
    severity: 'warning',
    specRef: `${SPEC_BASE}#versioning`,
    check: (profile) => {
      const map = profile.ucp?.supported_versions;
      if (!map) {
        return {
          passed: true,
          ruleId: 'ucp-supported-versions',
          message: 'No supported_versions declared (only the current version is advertised)',
          severity: 'warning',
        };
      }
      const entries = Object.entries(map);
      const badVersion = entries.filter(([v]) => !DATE_REGEX.test(v)).map(([v]) => v);
      const badUri = entries
        .filter(([, uri]) => typeof uri !== 'string' || !uri.startsWith('https://') || !isAbsoluteUrl(uri))
        .map(([v]) => v);
      const passed = badVersion.length === 0 && badUri.length === 0;
      return {
        passed,
        ruleId: 'ucp-supported-versions',
        message: passed
          ? `${entries.length} older version(s) advertised with leaf profile URIs`
          : `Malformed supported_versions (bad version keys: ${badVersion.join(', ') || 'none'}; bad URIs for: ${badUri.join(', ') || 'none'})`,
        severity: 'warning',
        details: { versions: entries.map(([v]) => v), badVersion, badUri },
        docUrl: `${SPEC_BASE}#versioning`,
      };
    },
  },

  // ── Services checks (2026-08-25: arrays of transport bindings) ────────
  {
    id: 'ucp-services-present',
    name: 'Services Object',
    description: 'ucp.services must be a non-empty object of binding arrays',
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
    description: 'Each service binding must have a version in YYYY-MM-DD format',
    severity: 'critical',
    specRef: `${SPEC_BASE}#services`,
    check: (profile) => {
      const entries = allEntries(profile.ucp?.services);
      const invalid = entries.filter(([, s]) => !s?.version || !DATE_REGEX.test(s.version));
      return {
        passed: invalid.length === 0 && entries.length > 0,
        ruleId: 'ucp-service-version',
        message: invalid.length === 0
          ? 'All service bindings have valid YYYY-MM-DD versions'
          : `${invalid.length} service binding(s) missing valid version`,
        severity: 'critical',
        details: { invalid: invalid.map(([k, s]) => `${k} (${s?.transport || 'no transport'})`) },
        docUrl: `${SPEC_BASE}#services`,
      };
    },
  },
  {
    id: 'ucp-service-spec',
    name: 'Service Spec URLs',
    description: 'Each service binding should have a spec URL pointing to its human-readable specification',
    severity: 'warning',
    specRef: `${SPEC_BASE}#services`,
    check: (profile) => {
      const entries = allEntries(profile.ucp?.services);
      const missing = entries.filter(([, s]) => !s?.spec);
      return {
        passed: missing.length === 0 && entries.length > 0,
        ruleId: 'ucp-service-spec',
        message: missing.length === 0
          ? 'All service bindings have spec URLs'
          : `${missing.length} service binding(s) missing spec URL`,
        severity: 'warning',
        details: { missing: missing.map(([k, s]) => `${k} (${s?.transport || 'no transport'})`) },
        docUrl: `${SPEC_BASE}#services`,
      };
    },
  },
  {
    id: 'ucp-service-transport',
    name: 'Transport Bindings',
    description: 'Each service must declare at least one binding; transport is a string (rest, mcp, a2a, embedded) and rest/mcp/a2a bindings need an endpoint',
    severity: 'critical',
    specRef: `${SPEC_BASE}#transport-layer`,
    check: (profile) => {
      const services = profile.ucp?.services || {};
      const problems: string[] = [];
      const summary: Array<{ name: string; transports: string[] }> = [];
      for (const [name, bindings] of Object.entries(services)) {
        const list = bindings || [];
        summary.push({ name, transports: list.map(b => b?.transport).filter(Boolean) as string[] });
        if (list.length === 0) {
          problems.push(`${name}: no bindings`);
          continue;
        }
        for (const b of list) {
          if (!b?.transport || !VALID_TRANSPORTS.includes(b.transport)) {
            problems.push(`${name}: invalid transport "${b?.transport}"`);
          } else if (b.transport !== 'embedded' && !b.endpoint) {
            problems.push(`${name} (${b.transport}): missing endpoint`);
          } else if (b.transport === 'embedded' && !b.config && !b.schema) {
            problems.push(`${name} (embedded): missing config and schema`);
          }
        }
      }
      const hasServices = Object.keys(services).length > 0;
      return {
        passed: problems.length === 0 && hasServices,
        ruleId: 'ucp-service-transport',
        message: problems.length === 0
          ? 'All services have valid transport bindings'
          : `Transport problems: ${problems.join('; ')}`,
        severity: 'critical',
        details: { problems, services: summary },
        docUrl: `${SPEC_BASE}#transport-layer`,
      };
    },
  },
  {
    id: 'ucp-transport-endpoints-https',
    name: 'HTTPS Endpoints',
    description: 'All binding endpoints must use HTTPS',
    severity: 'critical',
    specRef: `${SPEC_BASE}#security`,
    check: (profile) => {
      const insecure: string[] = [];
      for (const [name, b] of allEntries(profile.ucp?.services)) {
        if (b?.endpoint && !b.endpoint.startsWith('https://')) {
          insecure.push(`${name} (${b.transport})`);
        }
      }
      return {
        passed: insecure.length === 0,
        ruleId: 'ucp-transport-endpoints-https',
        message: insecure.length === 0
          ? 'All binding endpoints use HTTPS'
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
    description: 'ucp.capabilities must be a non-empty object of capability arrays',
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
    description: 'Each capability entry must have a version in YYYY-MM-DD format',
    severity: 'critical',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const entries = allEntries(profile.ucp?.capabilities);
      const invalid = entries.filter(([, c]) => !c?.version || !DATE_REGEX.test(c.version));
      return {
        passed: invalid.length === 0 && entries.length > 0,
        ruleId: 'ucp-capability-version',
        message: invalid.length === 0
          ? 'All capabilities have valid YYYY-MM-DD versions'
          : `${invalid.length} capability entry(ies) missing valid version`,
        severity: 'critical',
        details: { invalid: invalid.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#capabilities`,
      };
    },
  },
  {
    id: 'ucp-capability-schema',
    name: 'Capability Schema URLs',
    description: 'Each capability entry must have a JSON Schema URL (required for business profiles in 2026-08-25)',
    severity: 'critical',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const entries = allEntries(profile.ucp?.capabilities);
      const missing = entries.filter(([, c]) => !c?.schema);
      return {
        passed: missing.length === 0 && entries.length > 0,
        ruleId: 'ucp-capability-schema',
        message: missing.length === 0
          ? 'All capabilities have schema URLs'
          : `${missing.length} capability entry(ies) missing schema URL`,
        severity: 'critical',
        details: { missing: missing.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#capabilities`,
      };
    },
  },
  {
    id: 'ucp-capability-spec',
    name: 'Capability Spec URLs',
    description: 'Each capability entry should have a human-readable spec URL',
    severity: 'warning',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const entries = allEntries(profile.ucp?.capabilities);
      const missing = entries.filter(([, c]) => !c?.spec);
      return {
        passed: missing.length === 0 && entries.length > 0,
        ruleId: 'ucp-capability-spec',
        message: missing.length === 0
          ? 'All capabilities have spec URLs'
          : `${missing.length} capability entry(ies) missing spec URL`,
        severity: 'warning',
        details: { missing: missing.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#capabilities`,
      };
    },
  },
  {
    id: 'ucp-capability-extends',
    name: 'Extension Validity',
    description: 'Capabilities with "extends" (string or array) must reference existing parent capabilities',
    severity: 'warning',
    specRef: `${SPEC_BASE}#extensions`,
    check: (profile) => {
      const caps = profile.ucp?.capabilities || {};
      const capKeys = new Set(Object.keys(caps));
      const extensions = allEntries(caps).filter(([, c]) => c?.extends);
      const parentsOf = (c: { extends?: string | string[] }): string[] =>
        Array.isArray(c.extends) ? c.extends : c.extends ? [c.extends] : [];
      const orphans = extensions.filter(([, c]) => parentsOf(c).some(p => !capKeys.has(p)));
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

  // ── Schema authority check (replaces the old spec-binding semantics) ──
  {
    id: 'ucp-spec-binding',
    name: 'Schema URL Authority',
    description: 'In 2026-08-25 the schema URL is the normative authority: entities with a spec URL must carry a valid absolute schema URL. Differing spec/schema hosts are valid and are NOT a finding.',
    severity: 'warning',
    specRef: `${SPEC_BASE}#namespace-governance`,
    check: (profile) => {
      const problems: string[] = [];
      const examine = (kind: string, name: string, e: { spec?: string; schema?: string }, schemaExpected: boolean) => {
        if (e?.spec && !isAbsoluteUrl(e.spec)) problems.push(`${kind} ${name}: spec is not an absolute URL`);
        if (e?.schema && !isAbsoluteUrl(e.schema)) problems.push(`${kind} ${name}: schema is not an absolute URL`);
        if (schemaExpected && e?.spec && !e?.schema) problems.push(`${kind} ${name}: spec declared without the normative schema URL`);
      };
      // Schema is normative for capabilities and for rest/mcp/embedded
      // service bindings. An a2a binding carries no schema in the spec
      // (its interface is the Agent Card), and business payment handlers
      // may omit schema, so those are not flagged for a missing schema.
      for (const [name, s] of allEntries(profile.ucp?.services)) {
        examine('service', `${name} (${s.transport})`, s, s.transport !== 'a2a');
      }
      for (const [name, c] of allEntries(profile.ucp?.capabilities)) examine('capability', name, c, true);
      for (const [name, h] of allEntries(profile.ucp?.payment_handlers)) examine('payment_handler', name, h, false);
      return {
        passed: problems.length === 0,
        ruleId: 'ucp-spec-binding',
        message: problems.length === 0
          ? 'Schema URLs are present and absolute wherever a spec is declared'
          : `Schema authority problems: ${problems.join('; ')}`,
        severity: 'warning',
        details: { problems },
        docUrl: `${SPEC_BASE}#namespace-governance`,
      };
    },
  },

  // ── Payment handlers ──────────────────────────────────────────────────
  {
    id: 'ucp-payment-handlers',
    name: 'Payment Handlers',
    description: 'payment_handlers must be present on business profiles; each handler entry needs a version',
    severity: 'warning',
    specRef: `${SPEC_BASE}#payment-architecture`,
    check: (profile) => {
      const handlers = profile.ucp?.payment_handlers;
      if (!handlers) {
        return {
          passed: false,
          ruleId: 'ucp-payment-handlers',
          message: 'Missing ucp.payment_handlers (required on business profiles, may be an empty object)',
          severity: 'warning',
        };
      }
      const entries = allEntries(handlers);
      const invalid = entries.filter(([, h]) => !h?.version || !DATE_REGEX.test(h.version));
      return {
        passed: invalid.length === 0,
        ruleId: 'ucp-payment-handlers',
        message: entries.length === 0
          ? 'payment_handlers present but empty (no payment handlers declared)'
          : invalid.length === 0
            ? `${entries.length} payment handler(s) declared with valid versions`
            : `${invalid.length} payment handler(s) missing valid version`,
        severity: 'warning',
        details: { invalid: invalid.map(([k]) => k), total: entries.length },
        docUrl: `${SPEC_BASE}#payment-architecture`,
      };
    },
  },
  {
    id: 'ucp-payment-handler-id',
    name: 'Payment Handler IDs',
    description: 'Each payment handler entry must carry an "id" (required by the 2026-08-25 payment_handler schema)',
    severity: 'critical',
    specRef: `${SPEC_BASE}#payment-architecture`,
    check: (profile) => {
      const entries = allEntries(profile.ucp?.payment_handlers);
      const missing = entries.filter(([, h]) => !h?.id);
      return {
        passed: missing.length === 0,
        ruleId: 'ucp-payment-handler-id',
        message: entries.length === 0
          ? 'No payment handlers declared'
          : missing.length === 0
            ? 'All payment handlers have ids'
            : `${missing.length} payment handler(s) missing required id: ${missing.map(([k]) => k).join(', ')}`,
        severity: 'critical',
        details: { missing: missing.map(([k]) => k) },
        docUrl: `${SPEC_BASE}#payment-architecture`,
      };
    },
  },

  // ── Signing keys: keys[] replaces signing_keys ────────────────────────
  {
    id: 'ucp-keys',
    name: 'Signing Keys (keys[])',
    description: 'Signing keys must be published in the top-level keys[] array as JWK with kid and kty; signing_keys is the removed 2026-01-23 field',
    severity: 'warning',
    specRef: `${SPEC_BASE}#security`,
    check: (profile, raw) => {
      if (raw?.signing_keys && !raw?.keys) {
        return {
          passed: false,
          ruleId: 'ucp-keys',
          message: 'Profile publishes signing_keys (2026-01-23 field removed in 2026-08-25); verifiers read keys[] instead',
          severity: 'warning',
          details: { legacyField: 'signing_keys', count: raw.signing_keys.length },
          docUrl: `${SPEC_BASE}#security`,
        };
      }
      const keys = profile.keys;
      if (!keys || keys.length === 0) {
        return {
          passed: true,
          ruleId: 'ucp-keys',
          message: 'No signing keys declared (optional unless request signing or webhooks are used)',
          severity: 'warning',
        };
      }
      const invalid = keys.filter(k => !k.kid || !k.kty);
      return {
        passed: invalid.length === 0,
        ruleId: 'ucp-keys',
        message: invalid.length === 0
          ? `${keys.length} signing key(s) published in keys[] with kid and kty`
          : `${invalid.length} key(s) in keys[] missing required kid or kty`,
        severity: 'warning',
        details: { count: keys.length, invalid: invalid.length },
        docUrl: `${SPEC_BASE}#security`,
      };
    },
  },

  // ── 2026-08-25 capability surface (informational) ─────────────────────
  {
    id: 'ucp-cart-capability',
    name: 'Cart Capability',
    description: 'Whether the dev.ucp.shopping.cart capability (new in the current spec) is declared',
    severity: 'info',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const present = !!profile.ucp?.capabilities?.[UCP_CAPABILITIES.cart]?.length;
      return {
        passed: true,
        ruleId: 'ucp-cart-capability',
        message: present ? 'Cart capability declared' : 'Cart capability not declared',
        severity: 'info',
        details: { present },
      };
    },
  },
  {
    id: 'ucp-catalog-capability',
    name: 'Catalog Capabilities',
    description: 'Whether the catalog search/lookup capabilities are declared',
    severity: 'info',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const caps = profile.ucp?.capabilities || {};
      const search = !!caps[UCP_CAPABILITIES.catalogSearch]?.length;
      const lookup = !!caps[UCP_CAPABILITIES.catalogLookup]?.length;
      return {
        passed: true,
        ruleId: 'ucp-catalog-capability',
        message: `Catalog search: ${search ? 'declared' : 'not declared'}; catalog lookup: ${lookup ? 'declared' : 'not declared'}`,
        severity: 'info',
        details: { search, lookup },
      };
    },
  },
  {
    id: 'ucp-identity-linking',
    name: 'Identity Linking',
    description: 'Whether dev.ucp.common.identity_linking (OAuth 2.0) is declared, and with what providers',
    severity: 'info',
    specRef: `${SPEC_BASE}#capabilities`,
    check: (profile) => {
      const entries = profile.ucp?.capabilities?.[UCP_CAPABILITIES.identityLinking] || [];
      const providers = entries.flatMap(e => Object.keys((e.config as { providers?: object } | undefined)?.providers || {}));
      return {
        passed: true,
        ruleId: 'ucp-identity-linking',
        message: entries.length === 0
          ? 'Identity linking not declared'
          : `Identity linking declared${providers.length ? ` with provider(s): ${providers.join(', ')}` : ''}`,
        severity: 'info',
        details: { present: entries.length > 0, providers },
      };
    },
  },
  {
    id: 'ucp-payment-namespace',
    name: 'Payment Capability Namespace',
    description: 'Payment extensions must live under dev.ucp.common.payment.* in 2026-08-25',
    severity: 'info',
    specRef: `${SPEC_BASE}#payment-architecture`,
    check: (profile) => {
      const caps = Object.keys(profile.ucp?.capabilities || {});
      const paymentCaps = caps.filter(k => k.startsWith(UCP_PAYMENT_CAPABILITY_NAMESPACE));
      return {
        passed: true,
        ruleId: 'ucp-payment-namespace',
        message: paymentCaps.length > 0
          ? `Payment extension(s) under dev.ucp.common.payment.*: ${paymentCaps.join(', ')}`
          : 'No payment extension capabilities declared',
        severity: 'info',
        details: { paymentCapabilities: paymentCaps },
        docUrl: `${SPEC_BASE}#payment-architecture`,
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

/**
 * Run the UCP compliance rules. Accepts a profile document of any era:
 * the input is normalized to the 2026-08-25 model first, and rules also
 * receive the raw document so legacy-only fields stay visible.
 */
export async function checkUCPCompliance(
  profile: UCPBusinessProfile | UCPRawProfile,
  baseUrl: string
): Promise<ComplianceReport> {
  const raw = profile as UCPRawProfile;
  const normalized = normalizeUCPProfile(raw);
  const results: ComplianceResult[] = [];

  for (const rule of UCP_COMPLIANCE_RULES) {
    try {
      const result = rule.check(normalized, raw);
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
    specVersion: normalized.ucp?.version || 'unknown',
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
