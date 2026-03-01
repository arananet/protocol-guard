import type {
  UCPClientConfig,
  UCPBusinessProfile,
  UCPAuthConfig,
} from './types.js';

export class UCPClient {
  private baseUrl: string;
  private auth: UCPAuthConfig;
  private profile: UCPBusinessProfile | null = null;
  private accessToken: string | null = null;

  constructor(config: UCPClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.auth = config.auth || { type: 'none' };
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    if (this.auth.type === 'apiKey' && this.auth.apiKey) {
      headers['Authorization'] = `Bearer ${this.auth.apiKey}`;
    } else if (this.auth.type === 'oauth' && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    return headers;
  }

  /**
   * Fetch the UCP Business Profile from /.well-known/ucp
   * This is the primary discovery mechanism defined in the UCP spec.
   */
  async fetchBusinessProfile(): Promise<UCPBusinessProfile> {
    const response = await fetch(`${this.baseUrl}/.well-known/ucp`, {
      method: 'GET',
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch UCP profile: ${response.status} ${response.statusText}`);
    }

    this.profile = await response.json() as UCPBusinessProfile;
    return this.profile;
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

  /**
   * List all services declared in the profile.
   */
  getServices(): Record<string, unknown> {
    return this.profile?.ucp?.services || {};
  }

  /**
   * List all capabilities declared in the profile.
   */
  getCapabilities(): Record<string, unknown> {
    return this.profile?.ucp?.capabilities || {};
  }

  /**
   * Get the REST endpoint for a specific service (e.g. "dev.ucp.shopping").
   */
  getServiceRestEndpoint(serviceName: string): string | null {
    const service = this.profile?.ucp?.services?.[serviceName];
    return service?.transport?.rest?.endpoint || null;
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

    const response = await fetch(`${endpoint}/checkout-sessions`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(params),
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

    const response = await fetch(`${endpoint}/checkout-sessions/${sessionId}`, {
      method: 'GET',
      headers: this.getHeaders(),
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
        headers: this.getHeaders(),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    this.profile = null;
    this.accessToken = null;
  }
}

export function createUCPClient(config: UCPClientConfig): UCPClient {
  return new UCPClient(config);
}
