/// <reference lib="dom" />
// UCP request signing: HTTP Message Signatures (RFC 9421) with the
// Content-Digest companion header (RFC 9530), as required by the UCP
// 2026-08-25 signatures specification. Keys are JWK (RFC 7517); the
// matching public keys are published by each party in the `keys[]` array
// of its profile. Supported algorithms: ES256 (ECDSA P-256) and EdDSA
// (Ed25519), via WebCrypto (globalThis.crypto.subtle, Node 20+).

export interface UCPSignOptions {
  /** Key identifier, published as `kid` in the signer's profile `keys[]` */
  keyId: string;
  /** WebCrypto private key, or a private JWK to import on each call */
  privateKey: CryptoKey | JsonWebKey;
  /** Signature validity window in seconds (default 300) */
  expiresInSeconds?: number;
  /** Covered components (default: method, authority, path, digest, type) */
  coveredComponents?: string[];
  /** Signature label (default "ucp") */
  label?: string;
}

const DEFAULT_COMPONENTS = ['@method', '@authority', '@path', 'content-digest', 'content-type'];

function base64(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (const b of view) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function sha256Base64(body: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  return base64(digest);
}

/** RFC 9530 Content-Digest header value for a request body. */
export async function computeContentDigest(body: string): Promise<string> {
  return `sha-256=:${await sha256Base64(body)}:`;
}

function algorithmForKey(key: JsonWebKey | CryptoKey): { alg: string; signAlg: AlgorithmIdentifier | EcdsaParams } {
  if (key instanceof CryptoKey) {
    if (key.algorithm.name === 'Ed25519') return { alg: 'ed25519', signAlg: 'Ed25519' };
    if (key.algorithm.name === 'ECDSA') {
      const curve = (key.algorithm as EcKeyAlgorithm).namedCurve;
      if (curve === 'P-256') return { alg: 'ecdsa-p256-sha256', signAlg: { name: 'ECDSA', hash: 'SHA-256' } };
      if (curve === 'P-384') return { alg: 'ecdsa-p384-sha384', signAlg: { name: 'ECDSA', hash: 'SHA-384' } };
    }
    throw new Error(`Unsupported CryptoKey algorithm: ${key.algorithm.name}`);
  }
  const jwk = key as JsonWebKey;
  if (jwk.crv === 'Ed25519' || jwk.alg === 'EdDSA') return { alg: 'ed25519', signAlg: 'Ed25519' };
  if (jwk.crv === 'P-384' || jwk.alg === 'ES384') {
    return { alg: 'ecdsa-p384-sha384', signAlg: { name: 'ECDSA', hash: { name: 'SHA-384' } } as EcdsaParams };
  }
  return { alg: 'ecdsa-p256-sha256', signAlg: { name: 'ECDSA', hash: { name: 'SHA-256' } } as EcdsaParams };
}

async function importPrivateKey(key: CryptoKey | JsonWebKey): Promise<{ cryptoKey: CryptoKey; alg: string; signAlg: AlgorithmIdentifier | EcdsaParams }> {
  const info = algorithmForKey(key);
  if (key instanceof CryptoKey) return { cryptoKey: key, ...info };
  const jwk = key as JsonWebKey;
  const importAlg: AlgorithmIdentifier | EcKeyImportParams =
    info.alg === 'ed25519' ? 'Ed25519' : { name: 'ECDSA', namedCurve: jwk.crv === 'P-384' ? 'P-384' : 'P-256' };
  const cryptoKey = await crypto.subtle.importKey('jwk', jwk, importAlg, false, ['sign']);
  return { cryptoKey, ...info };
}

/**
 * Build the RFC 9421 signature base for a request. Exported so verifiers
 * (and tests) can reconstruct the exact string that was signed.
 */
export function buildSignatureBase(input: {
  method: string;
  url: string;
  headers: Record<string, string>;
  coveredComponents: string[];
  signatureParams: string;
}): string {
  const url = new URL(input.url);
  const lower = new Map(Object.entries(input.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const lines: string[] = [];
  for (const component of input.coveredComponents) {
    let value: string | undefined;
    switch (component) {
      case '@method': value = input.method.toUpperCase(); break;
      case '@authority': value = url.host; break;
      case '@path': value = url.pathname; break;
      case '@query': value = url.search ? url.search.slice(1) : ''; break;
      case '@scheme': value = url.protocol.replace(':', ''); break;
      default: value = lower.get(component);
    }
    if (value === undefined) throw new Error(`Cannot sign missing component: ${component}`);
    lines.push(`"${component}": ${value}`);
  }
  lines.push(`"@signature-params": ${input.signatureParams}`);
  return lines.join('\n');
}

/**
 * Sign an HTTP request per RFC 9421 and return the headers to merge into
 * it: Signature-Input, Signature and (when a body is present)
 * Content-Digest.
 */
export async function signUCPRequest(
  input: { method: string; url: string; headers?: Record<string, string>; body?: string },
  options: UCPSignOptions
): Promise<Record<string, string>> {
  const label = options.label || 'ucp';
  const headers: Record<string, string> = { ...(input.headers || {}) };
  const out: Record<string, string> = {};

  if (input.body !== undefined) {
    out['Content-Digest'] = await computeContentDigest(input.body);
    headers['content-digest'] = out['Content-Digest'];
  }

  const { cryptoKey, alg, signAlg } = await importPrivateKey(options.privateKey);
  const created = Math.floor(Date.now() / 1000);
  const expires = created + (options.expiresInSeconds ?? 300);
  const hasHeader = (name: string) => Object.keys(headers).some(k => k.toLowerCase() === name);
  const components = (options.coveredComponents || DEFAULT_COMPONENTS).filter(c => {
    if (c.startsWith('@')) return true;
    return hasHeader(c);
  });
  if (components.length === 0) throw new Error('No signable components available for this request');

  const componentList = components.map(c => `"${c}"`).join(' ');
  const signatureParams =
    `(${componentList});keyid="${options.keyId}";created=${created};expires=${expires};alg="${alg}";nonce="${base64(crypto.getRandomValues(new Uint8Array(16)))}"`;

  const base = buildSignatureBase({
    method: input.method,
    url: input.url,
    headers,
    coveredComponents: components,
    signatureParams,
  });

  const signature = await crypto.subtle.sign(signAlg, cryptoKey, new TextEncoder().encode(base));
  out['Signature-Input'] = `${label}=${signatureParams}`;
  out['Signature'] = `${label}=:${base64(signature)}:`;
  return out;
}

/** Convenience: build a UCPRequestSigner from static signing options. */
export function createUCPRequestSigner(options: UCPSignOptions) {
  return {
    async sign(input: { method: string; url: string; headers: Record<string, string>; body?: string }) {
      return signUCPRequest(input, options);
    },
  };
}
