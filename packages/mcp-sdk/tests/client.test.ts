import { describe, it, expect } from 'vitest';
import { MCPClient, createMCPClient } from '../src/client.js';
import type { MCPServerConfig } from '../src/types.js';

describe('MCP Client', () => {
  it('should create a client instance', () => {
    const config: MCPServerConfig = {
      name: 'test-server',
      url: 'http://localhost:3000/mcp',
      auth: { type: 'none' },
    };

    const client = createMCPClient(config);
    expect(client).toBeInstanceOf(MCPClient);
  });

  it('should have correct default values', () => {
    const config: MCPServerConfig = {
      name: 'test-server',
      url: 'http://localhost:3000/mcp',
      auth: { type: 'none' },
    };

    const client = createMCPClient(config);
    expect(client.getCapabilities()).toBeNull();
    expect(client.getServerInfo()).toBeNull();
  });

  it('starts with no era negotiated', () => {
    const client = createMCPClient({
      name: 'test-server',
      url: 'http://localhost:3000/mcp',
      auth: { type: 'none' },
    });

    expect(client.getEra()).toBe('unknown');
    expect(client.getProtocolVersion()).toBeNull();
    expect(client.getSupportedVersions()).toBeNull();
    expect(client.getComplianceContext().era).toBe('unknown');
  });
});
