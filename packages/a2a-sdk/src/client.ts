import type {
  A2AClientConfig,
  A2AAgentCard,
  A2ASendTaskRequest,
  A2ASendTaskResponse,
  A2AGetTaskRequest,
  A2AGetTaskResponse,
  A2ACancelTaskRequest,
  A2ATask,
  A2AAuthConfig,
} from './types.js';

export class A2AClient {
  private agentCard: A2AAgentCard | null = null;
  private auth: A2AAuthConfig;
  private accessToken: string | null = null;

  constructor(config: A2AClientConfig) {
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

  private getAgentEndpoint(method: string): string {
    if (!this.agentCard) {
      throw new Error('Agent card not loaded. Call fetchAgentCard() first.');
    }
    const baseUrl = this.agentCard.url.replace(/\/$/, '');
    return `${baseUrl}/${method}`;
  }

  async fetchAgentCard(url: string): Promise<A2AAgentCard> {
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Failed to fetch agent card: ${response.status} ${response.statusText}`);
    }

    const agentCard = await response.json() as A2AAgentCard;

    // Validate required fields
    if (!agentCard.name || !agentCard.url || !agentCard.version) {
      throw new Error('Invalid agent card: missing required fields');
    }

    this.agentCard = agentCard;
    return agentCard;
  }

  private async authenticateOAuth(): Promise<void> {
    if (!this.auth.oauth) return;

    const { oauth } = this.auth;
    const tokenEndpoint = oauth.tokenEndpoint || `${this.agentCard?.url}/oauth/token`;

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

  async sendTask(task: A2ASendTaskRequest): Promise<A2ASendTaskResponse> {
    if (this.auth.type === 'oauth') {
      await this.authenticateOAuth();
    }

    const response = await fetch(this.getAgentEndpoint('tasks/send'), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(task),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`A2A request failed: ${response.status} - ${error}`);
    }

    return response.json() as Promise<A2ASendTaskResponse>;
  }

  async getTask(params: A2AGetTaskRequest): Promise<A2AGetTaskResponse> {
    if (this.auth.type === 'oauth') {
      await this.authenticateOAuth();
    }

    const response = await fetch(this.getAgentEndpoint(`tasks/${params.id}`), {
      method: 'GET',
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`A2A request failed: ${response.status}`);
    }

    return response.json() as Promise<A2AGetTaskResponse>;
  }

  async cancelTask(params: A2ACancelTaskRequest): Promise<{ success: boolean }> {
    if (this.auth.type === 'oauth') {
      await this.authenticateOAuth();
    }

    const response = await fetch(this.getAgentEndpoint(`tasks/${params.id}/cancel`), {
      method: 'POST',
      headers: this.getHeaders(),
    });

    if (!response.ok) {
      throw new Error(`A2A cancel failed: ${response.status}`);
    }

    return { success: true };
  }

  getAgentCard(): A2AAgentCard | null {
    return this.agentCard;
  }

  async ping(): Promise<boolean> {
    if (!this.agentCard) return false;
    
    try {
      const response = await fetch(this.getAgentEndpoint('health'), {
        method: 'GET',
        headers: this.getHeaders(),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    this.agentCard = null;
    this.accessToken = null;
  }
}

export function createA2AClient(config: A2AClientConfig): A2AClient {
  return new A2AClient(config);
}
