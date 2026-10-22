import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createUCPClient } from '../src/client.js';
import { signUCPRequest, buildSignatureBase, computeContentDigest } from '../src/signing.js';
import { legacyProfile } from './fixtures.js';

const fetchMock = vi.fn();
vi.stubGlobal('fetch', fetchMock);

function jsonResponse(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

describe('UCPClient', () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it('fetches and normalizes a legacy profile, exposing the REST endpoint', async () => {
    fetchMock.mockResolvedValue(jsonResponse(legacyProfile));
    const client = createUCPClient({ name: 'test', baseUrl: 'https://legacy.example.com' });
    const profile = await client.fetchBusinessProfile();
    expect(profile.ucp.version).toBe('2026-01-23');
    expect(client.profileWasLegacy).toBe(true);
    expect(client.getServiceRestEndpoint('dev.ucp.shopping')).toBe('https://legacy.example.com/ucp/v1');
    expect(client.getServiceEndpoint('dev.ucp.shopping', 'mcp')).toBe('https://legacy.example.com/ucp/mcp');
    expect(client.getRawProfile()?.signing_keys).toHaveLength(1);
  });

  it('requests /.well-known/ucp and sends UCP-Agent when configured', async () => {
    fetchMock.mockResolvedValue(jsonResponse(legacyProfile));
    const client = createUCPClient({
      name: 'test',
      baseUrl: 'https://legacy.example.com',
      agentProfileUrl: 'https://agent.example/profile.json',
    });
    await client.fetchBusinessProfile();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://legacy.example.com/.well-known/ucp');
    expect(init.headers['UCP-Agent']).toBe('profile="https://agent.example/profile.json"');
  });

  it('reads the identity linking configuration from the normalized profile', async () => {
    const { currentProfile } = await import('./fixtures.js');
    fetchMock.mockResolvedValue(jsonResponse(currentProfile));
    const client = createUCPClient({ name: 'test', baseUrl: 'https://business.example.com' });
    await client.fetchBusinessProfile();
    const config = client.getIdentityLinkingConfig();
    expect(config?.providers?.['com.example.idp']?.[0].type).toBe('oauth2');
  });
});

describe('UCP request signing (RFC 9421)', () => {
  it('produces a Signature header that verifies against the public key', async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

    const body = JSON.stringify({ hello: 'ucp' });
    const url = 'https://business.example.com/ucp/v1/checkout-sessions';
    const requestHeaders = { 'Content-Type': 'application/json' };
    const signed = await signUCPRequest(
      { method: 'POST', url, headers: requestHeaders, body },
      { keyId: 'test-key-1', privateKey: privateJwk }
    );

    expect(signed['Content-Digest']).toBe(await computeContentDigest(body));
    expect(signed['Signature-Input']).toContain('keyid="test-key-1"');
    expect(signed['Signature']).toMatch(/^ucp=:.+:$/);

    // Rebuild the signature base exactly as the signer did and verify.
    const params = signed['Signature-Input'].slice('ucp='.length);
    const componentsMatch = params.match(/\(([^)]*)\)/);
    if (!componentsMatch) throw new Error('no component list in Signature-Input');
    const components = componentsMatch[1].split(' ').map(s => s.replace(/"/g, ''));
    const base = buildSignatureBase({
      method: 'POST',
      url,
      headers: {
        'content-type': 'application/json',
        'content-digest': signed['Content-Digest'],
      },
      coveredComponents: components,
      signatureParams: params,
    });

    const signatureBytes = Uint8Array.from(atob(signed['Signature'].slice('ucp=:'.length, -1)), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.publicKey,
      signatureBytes,
      new TextEncoder().encode(base)
    );
    expect(valid).toBe(true);
  });
});
