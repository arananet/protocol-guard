import type {
  MCPServerConfig,
  MCPInitializeResponse,
  MCPTool,
  MCPResource,
  MCPPrompt,
  MCPToolCallResponse,
  MCPJsonRPC,
  MCPAuthConfig,
} from './types.js';

export class MCPClient {
  private url: string;
  private auth: MCPAuthConfig;
  private capabilities: MCPInitializeResponse['capabilities'] | null = null;
  private serverInfo: MCPInitializeResponse['serverInfo'] | null = null;
  private accessToken: string | null = null;

  constructor(config: MCPServerConfig) {
    this.url = config.url.replace(/\/$/, '');
    this.auth = config.auth;
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.auth.type === 'apiKey' && this.auth.apiKey) {
      headers['Authorization'] = `Bearer ${this.auth.apiKey}`;
    } else if (this.auth.type === 'oauth' && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    return headers;
  }

  private async request<T>(method: string, params?: Record<string, unknown>): Promise<T> {
    const body: MCPJsonRPC = {
      jsonrpc: '2.0',
      id: this.generateId(),
      method,
      params,
    };

    const response = await fetch(this.url, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`MCP request failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as MCPJsonRPC;

    if (data.error) {
      throw new Error(`MCP error: ${data.error.code} - ${data.error.message}`);
    }

    return data.result as T;
  }

  async initialize(): Promise<MCPInitializeResponse> {
    // Handle OAuth if needed
    if (this.auth.type === 'oauth') {
      await this.authenticateOAuth();
    }

    const result = await this.request<MCPInitializeResponse>('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: {
        name: 'protocol-tester',
        version: '1.0.0',
      },
    });

    this.capabilities = result.capabilities;
    this.serverInfo = result.serverInfo;

    // Send initialized notification
    await this.request('notifications/initialized', {});

    return result;
  }

  private async authenticateOAuth(): Promise<void> {
    if (!this.auth.oauth) return;

    const { oauth } = this.auth;
    const tokenEndpoint = oauth.tokenEndpoint || `${this.url}/oauth/token`;

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

  async listTools(): Promise<MCPTool[]> {
    const result = await this.request<{ tools: MCPTool[] }>('tools/list');
    return result.tools;
  }

  async callTool(name: string, args?: Record<string, unknown>): Promise<MCPToolCallResponse> {
    return this.request<MCPToolCallResponse>('tools/call', { name, arguments: args });
  }

  async listResources(): Promise<MCPResource[]> {
    const result = await this.request<{ resources: MCPResource[] }>('resources/list');
    return result.resources;
  }

  async readResource(uri: string): Promise<{ contents: Array<{ text?: string; blob?: string }> }> {
    return this.request('resources/read', { uri });
  }

  async listPrompts(): Promise<MCPPrompt[]> {
    const result = await this.request<{ prompts: MCPPrompt[] }>('prompts/list');
    return result.prompts;
  }

  async getPrompt(name: string, args?: Record<string, unknown>): Promise<{ messages: Array<{ content: { type: string; text: string } }> }> {
    return this.request('prompts/get', { name, arguments: args });
  }

  getCapabilities(): MCPInitializeResponse['capabilities'] | null {
    return this.capabilities;
  }

  getServerInfo(): MCPInitializeResponse['serverInfo'] | null {
    return this.serverInfo;
  }

  async ping(): Promise<void> {
    await this.request('ping', {});
  }

  async close(): Promise<void> {
    // MCP doesn't have an explicit close, but we can clean up
    this.capabilities = null;
    this.serverInfo = null;
    this.accessToken = null;
  }
}

export function createMCPClient(config: MCPServerConfig): MCPClient {
  return new MCPClient(config);
}
