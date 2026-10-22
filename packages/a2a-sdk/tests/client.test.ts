import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createA2AClient, A2AError, legacyPartToPart, partToLegacyPart } from '../src/client.js';
import type { A2AAgentCard } from '../src/types.js';

const fetchMock = vi.fn();
vi.stubGlobal('fetch', fetchMock);

const card: A2AAgentCard = {
  name: 'Test Agent',
  description: 'Agent used in tests',
  version: '1.0.0',
  supportedInterfaces: [
    { url: 'https://agent.example.com/rpc', protocolBinding: 'JSONRPC', protocolVersion: '1.0' },
    { url: 'https://agent.example.com/rest', protocolBinding: 'HTTP+JSON', protocolVersion: '1.0' },
  ],
  capabilities: { streaming: true, pushNotifications: false },
  securitySchemes: { oauth: { oauth2SecurityScheme: {} } },
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'],
  skills: [],
};

function jsonResponse(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

/** Route card fetches (no body) and JSON-RPC calls (body.method) separately. */
function wireRpc(handler: (method: string, params: Record<string, unknown>) => unknown) {
  fetchMock.mockImplementation(async (url: string, init?: { method?: string; body?: string; headers?: Record<string, string> }) => {
    if (!init?.body) return jsonResponse(card);
    const body = JSON.parse(init.body);
    return jsonResponse(handler(body.method, body.params));
  });
}

async function loadedClient() {
  const client = createA2AClient({ name: 'test', agentCardUrl: 'https://agent.example.com/.well-known/agent-card.json' });
  await client.fetchAgentCard('https://agent.example.com/.well-known/agent-card.json');
  return client;
}

describe('A2AClient (A2A 1.0 JSON-RPC binding)', () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it('selects the JSONRPC interface endpoint from the card', async () => {
    wireRpc(() => ({ jsonrpc: '2.0', id: 1, result: { tasks: [] } }));
    const client = await loadedClient();
    expect(client.getRpcEndpoint()).toBe('https://agent.example.com/rpc');
  });

  it('sends SendMessage as JSON-RPC 2.0 with the A2A-Version header', async () => {
    let seen: { url: string; init: { headers: Record<string, string>; body: string } } | null = null;
    fetchMock.mockImplementation(async (url: string, init?: { body?: string; headers: Record<string, string> }) => {
      if (!init?.body) return jsonResponse(card);
      seen = { url, init: init as { headers: Record<string, string>; body: string } };
      return jsonResponse({
        jsonrpc: '2.0',
        id: 1,
        result: {
          task: {
            id: 'task-1',
            contextId: 'ctx-1',
            status: { state: 'TASK_STATE_COMPLETED' },
            artifacts: [],
            history: [],
          },
        },
      });
    });

    const client = await loadedClient();
    const result = await client.sendMessage({
      message: { messageId: 'm-1', role: 'ROLE_USER', parts: [{ text: 'hello' }] },
    });

    expect(result.task?.id).toBe('task-1');
    expect(result.task?.status.state).toBe('TASK_STATE_COMPLETED');
    if (!seen) throw new Error('RPC call not captured');
    const call = seen as { url: string; init: { headers: Record<string, string>; body: string } };
    expect(call.url).toBe('https://agent.example.com/rpc');
    expect(call.init.headers['A2A-Version']).toBe('1.0');
    const body = JSON.parse(call.init.body);
    expect(body.jsonrpc).toBe('2.0');
    expect(body.method).toBe('SendMessage');
    expect(body.params.message.parts).toEqual([{ text: 'hello' }]);
  });

  it('calls GetTask with the tasks id param', async () => {
    let seenMethod = '';
    wireRpc((method) => {
      seenMethod = method;
      return {
        jsonrpc: '2.0',
        id: 1,
        result: { id: 'task-9', status: { state: 'TASK_STATE_WORKING' } },
      };
    });
    const client = await loadedClient();
    const task = await client.getTask({ id: 'task-9' });
    expect(seenMethod).toBe('GetTask');
    expect(task.status.state).toBe('TASK_STATE_WORKING');
  });

  it('maps JSON-RPC error codes to named A2AError values', async () => {
    wireRpc(() => ({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32001, message: 'Task not found' },
    }));
    const client = await loadedClient();
    await expect(client.getTask({ id: 'missing' })).rejects.toMatchObject({
      name: 'A2AError',
      code: -32001,
      errorName: 'TaskNotFoundError',
    });
    await expect(client.getTask({ id: 'missing' })).rejects.toBeInstanceOf(A2AError);
  });

  it('sendTask adapter translates legacy parts and task state', async () => {
    let rpcParams: Record<string, unknown> | null = null;
    wireRpc((_method, params) => {
      rpcParams = params;
      return {
        jsonrpc: '2.0',
        id: 1,
        result: { task: { id: 'task-7', status: { state: 'TASK_STATE_COMPLETED' } } },
      };
    });
    const client = await loadedClient();
    const result = await client.sendTask({
      id: 'legacy-1',
      message: { role: 'user', parts: [{ type: 'text', text: 'hi there' }] },
    });
    expect(result).toEqual({ id: 'task-7', status: 'completed' });
    if (!rpcParams) throw new Error('params not captured');
    const params = rpcParams as { message: { role: string; parts: unknown[] } };
    expect(params.message.role).toBe('ROLE_USER');
    expect(params.message.parts).toEqual([{ text: 'hi there' }]);
  });
});

describe('part translators', () => {
  it('round-trips text and data parts', () => {
    expect(partToLegacyPart(legacyPartToPart({ type: 'text', text: 'abc' }))).toEqual({ type: 'text', text: 'abc' });
    expect(legacyPartToPart({ type: 'data', data: { a: 1 } })).toEqual({ data: { a: 1 } });
  });

  it('maps a legacy file part to the 1.0 url form', () => {
    const part = legacyPartToPart({ type: 'file', file: { uri: 'https://x/f.pdf', mimeType: 'application/pdf', name: 'f.pdf' } });
    expect(part).toEqual({ url: 'https://x/f.pdf', mediaType: 'application/pdf', filename: 'f.pdf' });
  });
});
