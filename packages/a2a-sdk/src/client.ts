import type {
  A2AClientConfig,
  A2AAgentCard,
  A2AAuthConfig,
  A2AJsonRpcResponse,
  A2AJsonRpcFailure,
  A2ASendMessageRequest,
  A2ASendMessageResponse,
  A2AGetTaskRequest,
  A2AListTasksRequest,
  A2AListTasksResponse,
  A2ACancelTaskRequest,
  A2ATask,
  A2AStreamResponse,
  A2ATaskPushNotificationConfig,
  A2AMessage,
  A2APart,
  A2ATaskState,
  A2ALegacyTaskStatus,
  A2ALegacyMessage,
  A2ALegacyPart,
  A2ASendTaskRequest,
  A2ASendTaskResponse,
  A2AGetTaskResponse,
} from './types.js';
import { A2A_METHODS, A2A_SPEC_VERSION } from './types.js';

/** A2A-specific JSON-RPC error names (spec section 5.4). */
export const A2A_ERROR_NAMES: Record<number, string> = {
  [-32700]: 'ParseError',
  [-32600]: 'InvalidRequestError',
  [-32601]: 'MethodNotFoundError',
  [-32602]: 'InvalidParamsError',
  [-32603]: 'InternalError',
  [-32001]: 'TaskNotFoundError',
  [-32002]: 'TaskNotCancelableError',
  [-32003]: 'PushNotificationNotSupportedError',
  [-32004]: 'UnsupportedOperationError',
  [-32005]: 'ContentTypeNotSupportedError',
  [-32006]: 'InvalidAgentResponseError',
  [-32007]: 'ExtendedAgentCardNotConfiguredError',
  [-32008]: 'ExtensionSupportRequiredError',
  [-32009]: 'VersionNotSupportedError',
};

/** Error thrown for JSON-RPC error responses and transport failures. */
export class A2AError extends Error {
  readonly code: number;
  readonly data?: unknown;
  readonly errorName: string;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = 'A2AError';
    this.code = code;
    this.data = data;
    this.errorName = A2A_ERROR_NAMES[code] || 'A2AError';
  }
}

const LEGACY_STATUS_TO_STATE: Record<A2ALegacyTaskStatus, A2ATaskState> = {
  pending: 'TASK_STATE_SUBMITTED',
  submitted: 'TASK_STATE_SUBMITTED',
  working: 'TASK_STATE_WORKING',
  completed: 'TASK_STATE_COMPLETED',
  failed: 'TASK_STATE_FAILED',
  canceled: 'TASK_STATE_CANCELED',
};

const STATE_TO_LEGACY_STATUS: Partial<Record<A2ATaskState, A2ALegacyTaskStatus>> = {
  TASK_STATE_UNSPECIFIED: 'pending',
  TASK_STATE_SUBMITTED: 'submitted',
  TASK_STATE_WORKING: 'working',
  TASK_STATE_COMPLETED: 'completed',
  TASK_STATE_FAILED: 'failed',
  TASK_STATE_CANCELED: 'canceled',
  TASK_STATE_INPUT_REQUIRED: 'working',
  TASK_STATE_REJECTED: 'failed',
  TASK_STATE_AUTH_REQUIRED: 'working',
};

function generateId(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  return `msg-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

/** Translate a pre-1.0 part (with `type`) into a 1.0 oneof part. */
export function legacyPartToPart(part: A2ALegacyPart): A2APart {
  switch (part.type) {
    case 'text':
      return { text: part.text ?? part.content ?? '' };
    case 'data':
      return { data: part.data ?? {} };
    case 'file':
    case 'image': {
      const file = part.file || part.image || {};
      const out: A2APart = {};
      if (file.bytes) out.raw = file.bytes;
      else if (file.uri) out.url = file.uri;
      if (file.mimeType) out.mediaType = file.mimeType;
      if (file.name) out.filename = file.name;
      return out;
    }
    case 'tool-use':
      return { data: { kind: 'tool-use', id: part.id, name: part.name, input: part.input } };
    case 'tool-result':
      return { data: { kind: 'tool-result', id: part.id, content: part.content, isError: part.isError } };
    default:
      return { data: part as unknown as Record<string, unknown> };
  }
}

/** Translate a 1.0 oneof part back into the pre-1.0 shape. */
export function partToLegacyPart(part: A2APart): A2ALegacyPart {
  if (part.text !== undefined) return { type: 'text', text: part.text };
  if (part.data !== undefined) {
    const d = part.data as { kind?: string; id?: string; name?: string; input?: Record<string, unknown>; content?: string; isError?: boolean };
    if (d && d.kind === 'tool-use') return { type: 'tool-use', id: d.id, name: d.name, input: d.input };
    if (d && d.kind === 'tool-result') return { type: 'tool-result', id: d.id, content: d.content, isError: d.isError };
    return { type: 'data', data: part.data as Record<string, unknown> };
  }
  return {
    type: part.mediaType?.startsWith('image/') ? 'image' : 'file',
    file: { mimeType: part.mediaType, uri: part.url, bytes: part.raw, name: part.filename },
  };
}

export function legacyMessageToMessage(message: A2ALegacyMessage, ids?: { contextId?: string; taskId?: string }): A2AMessage {
  return {
    messageId: generateId(),
    role: message.role === 'agent' ? 'ROLE_AGENT' : 'ROLE_USER',
    parts: (message.parts || []).map(legacyPartToPart),
    contextId: ids?.contextId,
    taskId: ids?.taskId,
    metadata: message.metadata,
  };
}

export function messageToLegacyMessage(message: A2AMessage): A2ALegacyMessage {
  return {
    role: message.role === 'ROLE_AGENT' ? 'agent' : 'user',
    parts: (message.parts || []).map(partToLegacyPart),
    metadata: message.metadata,
  };
}

export class A2AClient {
  private agentCard: A2AAgentCard | null = null;
  private auth: A2AAuthConfig;
  private accessToken: string | null = null;
  private protocolVersion: string;
  private extensions?: string[];
  private requestSeq = 0;

  constructor(config: A2AClientConfig) {
    this.auth = config.auth || { type: 'none' };
    this.protocolVersion = config.protocolVersion || A2A_SPEC_VERSION;
    this.extensions = config.extensions;
  }

  private getHeaders(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      // A2A 1.0: clients MUST send the A2A-Version service parameter on
      // every request; an empty value is interpreted as version 0.3.
      'A2A-Version': this.protocolVersion,
    };

    if (this.extensions?.length) {
      headers['A2A-Extensions'] = this.extensions.join(',');
    }
    if (this.auth.type === 'apiKey' && this.auth.apiKey) {
      headers['Authorization'] = `Bearer ${this.auth.apiKey}`;
    } else if (this.auth.type === 'oauth' && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }
    return { ...headers, ...(extra || {}) };
  }

  /**
   * The JSON-RPC endpoint of the loaded card: the first interface with
   * protocolBinding "JSONRPC", else the first interface, else the legacy
   * card `url`.
   */
  getRpcEndpoint(): string {
    if (!this.agentCard) {
      throw new Error('Agent card not loaded. Call fetchAgentCard() first.');
    }
    const interfaces = this.agentCard.supportedInterfaces || [];
    const jsonrpc = interfaces.find(i => (i.protocolBinding || '').toUpperCase() === 'JSONRPC');
    const chosen = jsonrpc || interfaces[0];
    const url = chosen?.url || this.agentCard.url;
    if (!url) throw new Error('Agent card declares no interface URL');
    return url.replace(/\/$/, '');
  }

  private getTenant(): string | undefined {
    const interfaces = this.agentCard?.supportedInterfaces || [];
    const jsonrpc = interfaces.find(i => (i.protocolBinding || '').toUpperCase() === 'JSONRPC');
    return (jsonrpc || interfaces[0])?.tenant;
  }

  async fetchAgentCard(url: string): Promise<A2AAgentCard> {
    const response = await fetch(url, { headers: this.getHeaders() });

    if (!response.ok) {
      throw new Error(`Failed to fetch agent card: ${response.status} ${response.statusText}`);
    }

    const agentCard = await response.json() as A2AAgentCard;

    if (!agentCard.name || !agentCard.version) {
      throw new Error('Invalid agent card: missing required fields');
    }
    const hasInterface = (agentCard.supportedInterfaces?.length || 0) > 0 || !!agentCard.url;
    if (!hasInterface) {
      throw new Error('Invalid agent card: no supportedInterfaces and no url');
    }

    this.agentCard = agentCard;
    return agentCard;
  }

  private async authenticateOAuth(): Promise<void> {
    if (!this.auth.oauth) return;

    const { oauth } = this.auth;
    const tokenEndpoint = oauth.tokenEndpoint || `${this.getRpcEndpoint()}/oauth/token`;

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

  private async ensureAuth(): Promise<void> {
    if (this.auth.type === 'oauth' && !this.accessToken) {
      await this.authenticateOAuth();
    }
  }

  /**
   * Core JSON-RPC 2.0 call of the A2A 1.0 binding. Throws A2AError on a
   * JSON-RPC error response (codes per spec section 5.4) or on transport
   * failure.
   */
  async call<TResult = unknown>(method: string, params?: Record<string, unknown>): Promise<TResult> {
    await this.ensureAuth();
    const id = ++this.requestSeq;
    const response = await fetch(this.getRpcEndpoint(), {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new A2AError(response.status, `A2A HTTP ${response.status}: ${text}`);
    }

    const json = await response.json() as A2AJsonRpcResponse<TResult>;
    if ((json as A2AJsonRpcFailure).error) {
      const err = (json as A2AJsonRpcFailure).error;
      throw new A2AError(err.code, err.message, err.data);
    }
    return (json as { result: TResult }).result;
  }

  /** SendMessage: starts or continues a task, or answers with a message. */
  async sendMessage(request: A2ASendMessageRequest): Promise<A2ASendMessageResponse> {
    const tenant = request.tenant ?? this.getTenant();
    return this.call<A2ASendMessageResponse>(A2A_METHODS.sendMessage, {
      ...request,
      ...(tenant ? { tenant } : {}),
    } as unknown as Record<string, unknown>);
  }

  /** SendStreamingMessage over SSE: yields StreamResponse events. */
  async *sendStreamingMessage(request: A2ASendMessageRequest): AsyncGenerator<A2AStreamResponse> {
    await this.ensureAuth();
    const id = ++this.requestSeq;
    const tenant = request.tenant ?? this.getTenant();
    const response = await fetch(this.getRpcEndpoint(), {
      method: 'POST',
      headers: this.getHeaders({ 'Accept': 'text/event-stream' }),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id,
        method: A2A_METHODS.sendStreamingMessage,
        params: { ...request, ...(tenant ? { tenant } : {}) },
      }),
    });

    if (!response.ok || !response.body) {
      const text = response.body ? await response.text() : '';
      throw new A2AError(response.status, `A2A streaming HTTP ${response.status}: ${text}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        const dataLine = frame.split('\n').find(l => l.startsWith('data:'));
        if (!dataLine) continue;
        const payload = JSON.parse(dataLine.slice(5).trim()) as A2AJsonRpcResponse<A2AStreamResponse>;
        if ((payload as A2AJsonRpcFailure).error) {
          const err = (payload as A2AJsonRpcFailure).error;
          throw new A2AError(err.code, err.message, err.data);
        }
        yield (payload as { result: A2AStreamResponse }).result;
      }
    }
  }

  /** GetTask. */
  async getTask(request: A2AGetTaskRequest): Promise<A2ATask> {
    const tenant = request.tenant ?? this.getTenant();
    return this.call<A2ATask>(A2A_METHODS.getTask, {
      ...request,
      ...(tenant ? { tenant } : {}),
    } as unknown as Record<string, unknown>);
  }

  /** ListTasks. */
  async listTasks(request: A2AListTasksRequest = {}): Promise<A2AListTasksResponse> {
    const tenant = request.tenant ?? this.getTenant();
    return this.call<A2AListTasksResponse>(A2A_METHODS.listTasks, {
      ...request,
      ...(tenant ? { tenant } : {}),
    } as unknown as Record<string, unknown>);
  }

  /** CancelTask. Returns the task in its canceled state. */
  async cancelTask(request: A2ACancelTaskRequest): Promise<A2ATask> {
    const tenant = request.tenant ?? this.getTenant();
    return this.call<A2ATask>(A2A_METHODS.cancelTask, {
      ...request,
      ...(tenant ? { tenant } : {}),
    } as unknown as Record<string, unknown>);
  }

  /** GetExtendedAgentCard: the authenticated, extended agent card. */
  async getExtendedAgentCard(): Promise<A2AAgentCard> {
    return this.call<A2AAgentCard>(A2A_METHODS.getExtendedAgentCard, {});
  }

  async createTaskPushNotificationConfig(config: A2ATaskPushNotificationConfig): Promise<A2ATaskPushNotificationConfig> {
    return this.call<A2ATaskPushNotificationConfig>(
      A2A_METHODS.createTaskPushNotificationConfig,
      config as unknown as Record<string, unknown>
    );
  }

  async getTaskPushNotificationConfig(taskId: string, configId: string): Promise<A2ATaskPushNotificationConfig> {
    return this.call<A2ATaskPushNotificationConfig>(A2A_METHODS.getTaskPushNotificationConfig, {
      taskId,
      id: configId,
    });
  }

  async listTaskPushNotificationConfigs(taskId: string): Promise<{ configs: A2ATaskPushNotificationConfig[] }> {
    return this.call<{ configs: A2ATaskPushNotificationConfig[] }>(
      A2A_METHODS.listTaskPushNotificationConfigs,
      { taskId }
    );
  }

  async deleteTaskPushNotificationConfig(taskId: string, configId: string): Promise<void> {
    await this.call(A2A_METHODS.deleteTaskPushNotificationConfig, { taskId, id: configId });
  }

  // ── Deprecated adapters over the 1.0 transport ────────────────────────

  /**
   * @deprecated Pre-1.0 helper kept for compatibility. Translates the old
   * request shape to SendMessage and the result back to { id, status }.
   * If the agent answers with a direct message instead of a task, the id
   * is empty and the status is reported as "completed".
   */
  async sendTask(task: A2ASendTaskRequest): Promise<A2ASendTaskResponse> {
    const result = await this.sendMessage({
      message: legacyMessageToMessage(task.message),
      metadata: task.metadata,
    });
    if (result.task) {
      return {
        id: result.task.id,
        status: STATE_TO_LEGACY_STATUS[result.task.status.state] || 'working',
      };
    }
    return { id: result.message?.taskId || '', status: 'completed' };
  }

  /**
   * @deprecated Pre-1.0 helper kept for compatibility. Use getTask(),
   * which returns the full 1.0 Task.
   */
  async getTaskLegacy(params: { id: string }): Promise<A2AGetTaskResponse> {
    const task = await this.getTask({ id: params.id });
    const lastMessage = task.history?.[task.history.length - 1] || task.status.message;
    return {
      id: task.id,
      status: STATE_TO_LEGACY_STATUS[task.status.state] || 'working',
      message: lastMessage ? messageToLegacyMessage(lastMessage) : undefined,
      metadata: task.metadata,
    };
  }

  /**
   * @deprecated Pre-1.0 helper kept for compatibility. Use cancelTask(),
   * which returns the canceled Task.
   */
  async cancelTaskLegacy(params: { id: string }): Promise<{ success: boolean }> {
    await this.cancelTask({ id: params.id });
    return { success: true };
  }

  getAgentCard(): A2AAgentCard | null {
    return this.agentCard;
  }

  async ping(): Promise<boolean> {
    if (!this.agentCard) return false;
    try {
      await this.listTasks({ pageSize: 1 });
      return true;
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

export { LEGACY_STATUS_TO_STATE, STATE_TO_LEGACY_STATUS };
