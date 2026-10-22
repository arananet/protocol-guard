import { describe, it, expect } from 'vitest';
import { normalizeUCPProfile, isLegacyUCPProfile } from '../src/client.js';
import { currentProfile, legacyProfile } from './fixtures.js';

describe('normalizeUCPProfile', () => {
  it('keeps a 2026-08-25 profile structurally intact', () => {
    const normalized = normalizeUCPProfile(currentProfile);
    expect(normalized.ucp.version).toBe('2026-08-25');
    expect(normalized.ucp.services['dev.ucp.shopping']).toHaveLength(4);
    expect(normalized.ucp.services['dev.ucp.shopping'][0].transport).toBe('rest');
    expect(normalized.keys).toHaveLength(1);
    expect(normalized.keys?.[0].kid).toBe('business_2025');
  });

  it('decomposes a legacy transport object into per-transport bindings', () => {
    const normalized = normalizeUCPProfile(legacyProfile);
    const bindings = normalized.ucp.services['dev.ucp.shopping'];
    expect(bindings).toHaveLength(2);
    const rest = bindings.find(b => b.transport === 'rest');
    expect(rest?.endpoint).toBe('https://legacy.example.com/ucp/v1');
    expect(rest?.version).toBe('2026-01-23');
    expect(rest?.schema).toContain('rest.openapi.json');
    const mcp = bindings.find(b => b.transport === 'mcp');
    expect(mcp?.endpoint).toBe('https://legacy.example.com/ucp/mcp');
  });

  it('wraps single legacy capabilities and payment handlers in arrays', () => {
    const normalized = normalizeUCPProfile(legacyProfile);
    expect(Array.isArray(normalized.ucp.capabilities['dev.ucp.shopping.checkout'])).toBe(true);
    expect(normalized.ucp.capabilities['dev.ucp.shopping.checkout'][0].version).toBe('2026-01-23');
    expect(Array.isArray(normalized.ucp.payment_handlers?.['com.google.pay'])).toBe(true);
  });

  it('maps legacy signing_keys to keys', () => {
    const normalized = normalizeUCPProfile(legacyProfile);
    expect(normalized.keys).toHaveLength(1);
    expect(normalized.keys?.[0].kid).toBe('legacy-1');
  });

  it('does not mutate the input document', () => {
    const snapshot = JSON.stringify(legacyProfile);
    normalizeUCPProfile(legacyProfile);
    expect(JSON.stringify(legacyProfile)).toBe(snapshot);
  });
});

describe('isLegacyUCPProfile', () => {
  it('flags the 2026-01-23 shape', () => {
    expect(isLegacyUCPProfile(legacyProfile)).toBe(true);
  });

  it('accepts the 2026-08-25 shape', () => {
    expect(isLegacyUCPProfile(currentProfile)).toBe(false);
  });
});
