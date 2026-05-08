/**
 * SSRF guard and header sanitization utilities.
 *
 * Call assertPublicUrl() before every outbound fetch() to prevent
 * Server-Side Request Forgery targeting cloud metadata services,
 * private subnets, and loopback addresses.
 */

// ─── Private IP Detection ─────────────────────────────────────────────────────

function isPrivateIPv4(hostname: string): boolean {
  const parts = hostname.split('.');
  if (parts.length !== 4) return false;
  const nums = parts.map(Number);
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = nums;
  return (
    a === 10 ||                               // 10.0.0.0/8
    (a === 172 && b >= 16 && b <= 31) ||      // 172.16.0.0/12
    (a === 192 && b === 168) ||               // 192.168.0.0/16
    a === 127 ||                              // 127.0.0.0/8 loopback
    (a === 169 && b === 254) ||               // 169.254.0.0/16 link-local (AWS IMDS)
    a === 0 ||                                // 0.0.0.0/8 this-network
    (a === 100 && b >= 64 && b <= 127) ||     // 100.64.0.0/10 shared address space
    a === 240 ||                              // 240.0.0.0/4 reserved
    a === 255                                 // broadcast
  );
}

function isPrivateIPv6(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return (
    h === '::1' ||
    h.startsWith('fc') ||   // unique local
    h.startsWith('fd') ||   // unique local
    h.startsWith('fe80') || // link-local
    h === '::' ||
    h === '0:0:0:0:0:0:0:1' ||
    h === '0:0:0:0:0:0:0:0'
  );
}

// ─── Blocked Hostnames ────────────────────────────────────────────────────────

const BLOCKED_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata.google',
]);

const BLOCKED_HOSTNAME_PATTERNS: RegExp[] = [
  /\bmetadata\.google\b/i,
  /\binstance-data\b/i,
  /\bimds\b/i,
];

// ─── Public ───────────────────────────────────────────────────────────────────

/**
 * Throws if rawUrl is invalid, uses a non-HTTP(S) protocol, or resolves to a
 * private/reserved/cloud-metadata destination.
 */
export function assertPublicUrl(rawUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL');
  }

  const { protocol, hostname } = parsed;

  if (protocol !== 'http:' && protocol !== 'https:') {
    throw new Error(`Protocol "${protocol}" is not allowed. Only http and https are permitted.`);
  }

  const host = hostname.toLowerCase();

  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new Error('URL targets a local hostname');
  }

  if (isPrivateIPv4(host)) {
    throw new Error('URL targets a private or reserved IP address');
  }

  if (isPrivateIPv6(host)) {
    throw new Error('URL targets a private IPv6 address');
  }

  if (BLOCKED_HOSTNAMES.has(host)) {
    throw new Error('URL targets a blocked cloud metadata hostname');
  }

  for (const pattern of BLOCKED_HOSTNAME_PATTERNS) {
    if (pattern.test(host)) {
      throw new Error('URL targets a blocked hostname');
    }
  }
}

// ─── Header Sanitization ──────────────────────────────────────────────────────

// Headers that could manipulate routing, proxies, or enable response splitting.
const FORBIDDEN_HEADER_NAMES = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'upgrade',
  'proxy-authorization',
  'proxy-authenticate',
  'te',
  'trailer',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'forwarded',
  'via',
]);

/**
 * Returns a sanitized header name.
 * Strips CRLF/null bytes and throws for hop-by-hop or routing headers.
 * Falls back to 'Authorization' when name is falsy or forbidden.
 */
export function sanitizeAuthHeader(name: string | undefined): string {
  if (!name) return 'Authorization';
  const clean = name.replace(/[\r\n\x00]/g, '').trim();
  if (!clean || FORBIDDEN_HEADER_NAMES.has(clean.toLowerCase())) return 'Authorization';
  return clean;
}

/**
 * Strips CRLF/null bytes from a header value to prevent response splitting.
 */
export function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n\x00]/g, '');
}

/**
 * Converts a raw customHeaders array into a safe Record<string, string>.
 * Silently drops entries with forbidden names, empty keys, or empty values.
 */
export function sanitizeCustomHeaders(customHeaders: unknown): Record<string, string> {
  const result: Record<string, string> = {};
  if (!Array.isArray(customHeaders)) return result;
  for (const h of customHeaders) {
    if (!h || typeof h !== 'object') continue;
    const rawKey = typeof h.key === 'string' ? h.key : '';
    const rawValue = typeof h.value === 'string' ? h.value : String(h.value ?? '');
    if (!rawKey || !rawValue) continue;
    const cleanKey = rawKey.replace(/[\r\n\x00]/g, '').trim();
    if (!cleanKey || FORBIDDEN_HEADER_NAMES.has(cleanKey.toLowerCase())) continue;
    result[cleanKey] = sanitizeHeaderValue(rawValue);
  }
  return result;
}
