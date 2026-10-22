import type {
  UCPClientConfig,
  UCPBusinessProfile,
  UCPRawProfile,
  UCPService,
  UCPCapability,
  UCPPaymentHandler,
  UCPAuthConfig,
  UCPTransport,
  UCPIdentityLinkingConfig,
  UCPOAuthServerMetadata,
  LegacyUCPService,
} from './types.js';
import { UCP_CAPABILITIES } from './types.js';

const TRANSPORTS: UCPTransport[] = ['rest', 'mcp', 'a2a', 'embedded'];

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function isLegacyService(value: unknown): value is LegacyUCPService {
  return isRecord(value) && isRecord((value as unknown as LegacyUCPService).transport);
}

/**
 * Normalize a profile document of any UCP era (2026-01-23 or 2026-08-25)
 * into the 2026-08-25 model:
 *   - record values become arrays of entities
 *   - a legacy service (transport object) is decomposed into one binding
 *     per transport present, inheriting version/spec/schema
 *   - top-level `signing_keys` is mapped to `keys`
 *
 * Pure function: the input document is not mutated.
 */
export function normalizeUCPProfile(raw: UCPRawProfile): UCPBusinessProfile {
  const services: Record<string, UCPService[]> = {};
  for (const [name, value] of Object.entries(raw.ucp?.services || {})) {
    const bindings: UCPService[] = [];
    for (const entry of asArray(value as UCPService | LegacyUCPService)) {
      if (isLegacyService(entry)) {
        for (const transport of TRANSPORTS) {
          const binding = entry.transport[transport];
          if (!binding) continue;
          bindings.push({
            version: entry.version,
            spec: entry.spec,
            schema: binding.schema,
            transport,
            endpoint: binding.endpoint,
          });
        }
      } else if (isRecord(entry)) {
        bindings.push(entry as unknown as UCPService);
      }
    }
    services[name] = bindings;
  }

  const capabilities: Record<string, UCPCapability[]> = {};
  for (const [name, value] of Object.entries(raw.ucp?.capabilities || {})) {
    capabilities[name] = asArray(value as UCPCapability).filter(isRecord) as UCPCapability[];
  }

  const paymentHandlers: Record<string, UCPPaymentHandler[]> = {};
  for (const [name, value] of Object.entries(raw.ucp?.payment_handlers || {})) {
    paymentHandlers[name] = asArray(value as UCPPaymentHandler).filter(isRecord) as UCPPaymentHandler[];
  }

  return {
    ucp: {
      version: raw.ucp?.version,
      supported_versions: raw.ucp?.supported_versions,
      services,
      capabilities,
      payment_handlers: paymentHandlers,
    },
    keys: raw.keys || raw.signing_keys || [],
  };
}

/** True when a raw profile uses any 2026-01-23-only shape. */
export function isLegacyUCPProfile(raw: UCPRawProfile): boolean {
  if (raw.signing_keys && !raw.keys) return true;
  for (const value of Object.values(raw.ucp?.services || {})) {
    if (!Array.isArray(value)) return true;
    if (value.some(isLegacyService)) return true;
  }
  for (const value of Object.values(raw.ucp?.capabilities || {})) {
    if (!Array.isArray(value)) return true;
  }
  for (const value of Object.values(raw.ucp?.payment_handlers || {})) {
    if (!Array.isArray(value)) return true;
  }
  return false;
}

export class UCPClient {
  private baseUrl: string;
  private auth: UCPAuthConfig;
  private agentProfileUrl?: string;
  private signer?: UCPClientConfig['signer'];
  private profile: UCPBusinessProfile | null = null;
  private rawProfile: UCPRawProfile | null = null;
  private accessToken: string | null = null;

  constructor(config: UCPClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.auth = config.auth || { type: 'none' };
    this.agentProfileUrl = config.agentProfileUrl;
    this.signer = config.signer;
  }

  private async buildHeaders(body?: string): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    if (this.agentProfileUrl) {
      headers['UCP-Agent'] = `profile="${this.agentProfileUrl}"`;
    }

    if (this.auth.type === 'apiKey' && this.auth.apiKey) {
      headers['Authorization'] = `Bearer ${this.auth.apiKey}`;
    } else if (this.auth.type === 'oauth' && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    return headers;
  }

  private async signedFetch(url: string, init: { method: string; body?: string }): Promise<Response> {
    const headers = await this.buildHeaders(init.body);
    if (this.signer) {
      const signatureHeaders = await this.signer.sign({
        method: init.method,
        url,
        headers,
        body: init.body,
      });
      Object.assign(headers, signatureHeaders);
    }
    return fetch(url, { method: init.method, headers, body: init.body });
  }

  /**
   * Fetch the UCP Business Profile from /.well-known/ucp and normalize it
   * to the 2026-08-25 model. This is the primary discovery mechanism
   * defined in the UCP spec.
   */
  async fetchBusinessProfile(): Promise<UCPBusinessProfile> {
    const response = await fetch(`${this.baseUrl}/.well-known/ucp`, {
      method: 'GET',
      headers: await this.buildHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch UCP profile: ${response.status} ${response.statusText}`);
    }

    const raw = await response.json() as UCPRawProfile;
    this.rawProfile = raw;
    this.profile = normalizeUCPProfile(raw);
    return this.profile;
  }

  /** The profile document exactly as served, before normalization. */
  getRawProfile(): UCPRawProfile | null {
    return this.rawProfile;
  }

  /** True when the served profile used 2026-01-23 shapes. */
  get profileWasLegacy(): boolean {
    return this.rawProfile ? isLegacyUCPProfile(this.rawProfile) : false;
  }

  private async authenticateOAuth(): Promise<void> {
    if (!this.auth.oauth) return;

    const { oauth } = this.auth;
    const tokenEndpoint = oauth.tokenEndpoint || `${this.baseUrl}/oauth/token`;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: oauth.clientId,
        client_secret: oauth.clientSecret || '',
        scope: oauth.scopes?.join(' ') || 'read write',
      }),
    });

    if (!response.ok) {
      throw new Error(`OAuth authentication failed: ${response.status}`);
    }

    const data = await response.json() as { access_token: string };
    this.accessToken = data.access_token;
  }

  /** All service bindings declared in the profile, keyed by service name. */
  getServices(): Record<string, UCPService[]> {
    return this.profile?.ucp?.services || {};
  }

  /** All capabilities declared in the profile, keyed by capability name. */
  getCapabilities(): Record<string, UCPCapability[]> {
    return this.profile?.ucp?.capabilities || {};
  }

  /** Bindings of one service (one entry per transport). */
  getServiceBindings(serviceName: string): UCPService[] {
    return this.profile?.ucp?.services?.[serviceName] || [];
  }

  /** Endpoint of one service binding for a given transport. */
  getServiceEndpoint(serviceName: string, transport: UCPTransport): string | null {
    const binding = this.getServiceBindings(serviceName).find(b => b.transport === transport);
    return binding?.endpoint || null;
  }

  /**
   * Get the REST endpoint for a specific service (e.g. "dev.ucp.shopping").
   */
  getServiceRestEndpoint(serviceName: string): string | null {
    return this.getServiceEndpoint(serviceName, 'rest');
  }

  /**
   * Identity Linking (2026-08-25): read the
   * `dev.ucp.common.identity_linking` capability configuration.
   */
  getIdentityLinkingConfig(): UCPIdentityLinkingConfig | null {
    const entries = this.profile?.ucp?.capabilities?.[UCP_CAPABILITIES.identityLinking] || [];
    const config = entries[0]?.config as UCPIdentityLinkingConfig | undefined;
    return config || null;
  }

  /**
   * Discover the business OAuth 2.0 authorization server metadata
   * (RFC 8414) used by Identity Linking, at
   * /.well-known/oauth-authorization-server.
   */
  async fetchOAuthMetadata(): Promise<UCPOAuthServerMetadata> {
    const response = await fetch(`${this.baseUrl}/.well-known/oauth-authorization-server`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch OAuth metadata: ${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<UCPOAuthServerMetadata>;
  }

  /**
   * Create a checkout session via the REST transport of the shopping service.
   */
  async createCheckoutSession(params: Record<string, unknown>): Promise<unknown> {
    if (this.auth.type === 'oauth') {
      await this.authenticateOAuth();
    }

    const endpoint = this.getServiceRestEndpoint('dev.ucp.shopping');
    if (!endpoint) {
      throw new Error('UCP shopping service REST endpoint not available');
    }

    const body = JSON.stringify(params);
    const response = await this.signedFetch(`${endpoint}/checkout-sessions`, {
      method: 'POST',
      body,
    });

    if (!response.ok) {
      throw new Error(`Checkout session creation failed: ${response.status}`);
    }

    return response.json();
  }

  async getCheckoutSession(sessionId: string): Promise<unknown> {
    if (this.auth.type === 'oauth') {
      await this.authenticateOAuth();
    }

    const endpoint = this.getServiceRestEndpoint('dev.ucp.shopping');
    if (!endpoint) {
      throw new Error('UCP shopping service REST endpoint not available');
    }

    const response = await this.signedFetch(`${endpoint}/checkout-sessions/${sessionId}`, {
      method: 'GET',
    });

    if (!response.ok) {
      throw new Error(`Failed to get checkout session: ${response.status}`);
    }

    return response.json();
  }

  getProfile(): UCPBusinessProfile | null {
    return this.profile;
  }

  async ping(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/.well-known/ucp`, {
        method: 'HEAD',
        headers: await this.buildHeaders(),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    this.profile = null;
    this.rawProfile = null;
    this.accessToken = null;
  }
}

export function createUCPClient(config: UCPClientConfig): UCPClient {
  return new UCPClient(config);
}
