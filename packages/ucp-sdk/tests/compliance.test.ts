import { describe, it, expect } from 'vitest';
import { checkUCPCompliance } from '../src/compliance/checker.js';
import { currentProfile, legacyProfile } from './fixtures.js';

function ruleById(report: Awaited<ReturnType<typeof checkUCPCompliance>>, id: string) {
  const result = report.results.find(r => r.ruleId === id);
  if (!result) throw new Error(`rule ${id} missing from report`);
  return result;
}

describe('UCP compliance checker (2026-08-25)', () => {
  it('passes a valid 2026-08-25 profile with zero critical failures', async () => {
    const report = await checkUCPCompliance(currentProfile, 'https://business.example.com');
    expect(report.failedCount).toBe(0);
    expect(report.specVersion).toBe('2026-08-25');
  });

  it('does not flag differing spec/schema hosts (ucp-spec-binding regression)', async () => {
    const report = await checkUCPCompliance(currentProfile, 'https://business.example.com');
    const binding = ruleById(report, 'ucp-spec-binding');
    expect(binding.passed).toBe(true);
  });

  it('fails ucp-spec-binding when a spec is declared without the normative schema', async () => {
    const broken = JSON.parse(JSON.stringify(currentProfile));
    delete broken.ucp.capabilities['dev.ucp.shopping.checkout'][0].schema;
    const report = await checkUCPCompliance(broken, 'https://business.example.com');
    expect(ruleById(report, 'ucp-spec-binding').passed).toBe(false);
    expect(ruleById(report, 'ucp-capability-schema').passed).toBe(false);
  });

  it('accepts well-formed supported_versions and flags malformed ones', async () => {
    const ok = await checkUCPCompliance(currentProfile, 'https://business.example.com');
    expect(ruleById(ok, 'ucp-supported-versions').passed).toBe(true);

    const broken = JSON.parse(JSON.stringify(currentProfile));
    broken.ucp.supported_versions = { 'not-a-date': 'http://insecure.example.com/profile' };
    const bad = await checkUCPCompliance(broken, 'https://business.example.com');
    expect(ruleById(bad, 'ucp-supported-versions').passed).toBe(false);
  });

  it('requires payment handler ids', async () => {
    const broken = JSON.parse(JSON.stringify(currentProfile));
    delete broken.ucp.payment_handlers['com.example.processor_tokenizer'][0].id;
    const report = await checkUCPCompliance(broken, 'https://business.example.com');
    expect(ruleById(report, 'ucp-payment-handler-id').passed).toBe(false);
    expect(report.failedCount).toBeGreaterThan(0);
  });

  it('reads legacy profiles tolerantly but flags signing_keys via ucp-keys', async () => {
    const report = await checkUCPCompliance(legacyProfile, 'https://legacy.example.com');
    // Transport decomposition: legacy rest/mcp bindings are found and pass.
    expect(ruleById(report, 'ucp-service-transport').passed).toBe(true);
    // The legacy key field is a finding, not a pass.
    const keys = ruleById(report, 'ucp-keys');
    expect(keys.passed).toBe(false);
    expect(keys.message).toContain('signing_keys');
  });

  it('flags keys without kid or kty', async () => {
    const broken = JSON.parse(JSON.stringify(currentProfile));
    broken.keys = [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }];
    const report = await checkUCPCompliance(broken, 'https://business.example.com');
    expect(ruleById(report, 'ucp-keys').passed).toBe(false);
  });
});
