// A2A Protocol Types - Based on https://a2a-protocol.org/latest/specification/
// Spec version: 1.0 (canonical model: specification/a2a.proto of the
// official google-a2a/A2A repository; JSON serialization uses the proto
// camelCase field names).
//
// What changed versus the 0.2.x / 0.3.0 model this file used before:
//   - task states are TASK_STATE_* enum strings and Task.status is an
//     object { state, message?, timestamp? }, not a bare string.
//   - Part is a oneof with NO `type`/`kind` discriminator: exactly one of
//     text / raw / url / data, plus mediaType / filename / metadata.
//   - Message requires messageId and uses role ROLE_USER / ROLE_AGENT.
//   - AgentCard interfaces are `supportedInterfaces` with protocolBinding
//     and protocolVersion per interface; security uses securitySchemes and
//     securityRequirements.
// The pre-1.0 shapes are kept at the bottom, marked @deprecated, so the
// client's legacy adapters can translate them.

export const A2A_SPEC_VERSION = '1.0';

export interface A2AClientConfig {
  id?: string;
  name: string;
  agentCardUrl: string;
  auth?: A2AAuthConfig;
  /** Protocol version sent in the A2A-Version header (default "1.0") */
  protocolVersion?: string;
  /** Extra extension URIs to send in the A2A-Extensions header */
  extensions?: string[];
}

export interface A2AAuthConfig {
  type: 'none' | 'apiKey' | 'oauth';
  apiKey?: string;
  oauth?: A2AOAuthConfig;
}

export interface A2AOAuthConfig {
  clientId: string;
  clientSecret?: string;
  tokenEndpoint?: string;
  scopes?: string[];
}

// ============================================================
// Agent Card (1.0)
// ============================================================

export interface A2AAgentCard {
  name: string;
  description: string;
  /** Ordered list of supported interfaces; the first entry is preferred */
  supportedInterfaces: A2AAgentInterface[];
  version: string;
  capabilities: A2AAgentCapabilities;
  securitySchemes?: Record<string, A2ASecurityScheme>;
  securityRequirements?: A2ASecurityRequirement[];
  /** Media types the agent accepts across all skills (required in 1.0) */
  defaultInputModes?: string[];
  /** Media types the agent produces across all skills (required in 1.0) */
  defaultOutputModes?: string[];
  skills?: A2AAgentSkill[];
  signatures?: A2AAgentCardSignature[];
  iconUrl?: string;
  documentationUrl?: string;
  provider?: A2AProvider;
  /** Non-standard field some agents publish; read tolerantly */
  supportedModels?: string[];
  /**
   * Legacy card-level fields, still read tolerantly when present.
   * `url` was the single endpoint before supportedInterfaces existed.
   */
  url?: string;
  /** @deprecated In 1.0 the version lives on each interface. */
  protocolVersion?: string;
  /** @deprecated Superseded by supportedInterfaces. */
  preferredTransport?: string;
  /** @deprecated Superseded by supportedInterfaces. */
  additionalInterfaces?: A2AAgentInterface[];
  /** @deprecated Superseded by securitySchemes/securityRequirements. */
  authentication?: A2AAuthentication;
  /** @deprecated Renamed to securityRequirements in 1.0. */
  security?: Array<Record<string, string[]>>;
  supportsAuthenticatedExtendedCard?: boolean;
  tags?: string[];
}

export interface A2AAgentInterface {
  url: string;
  /** Core bindings: "JSONRPC", "GRPC", "HTTP+JSON" (open string) */
  protocolBinding: string;
  /** A2A protocol version exposed at this interface, e.g. "1.0" */
  protocolVersion: string;
  /** Opaque tenant routing value; when set, clients MUST send it */
  tenant?: string;
  /** @deprecated 0.2.x/0.3.x name for protocolBinding. */
  transport?: string;
}

export interface A2ASecurityRequirement {
  schemes: Record<string, string[]>;
}

export interface A2ASecurityScheme {
  type?: string;
  apiKeySecurityScheme?: { description?: string; location?: string; name?: string };
  httpAuthSecurityScheme?: { description?: string; scheme?: string; bearerFormat?: string };
  oauth2SecurityScheme?: { description?: string; flows?: Record<string, unknown> };
  openIdConnectSecurityScheme?: { description?: string; openIdConnectUrl?: string };
  mutualTlsSecurityScheme?: { description?: string };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

export interface A2AAgentCardSignature {
  /** base64url-encoded JWS protected header */
  protected: string;
  /** base64url-encoded signature */
  signature: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  header?: Record<string, any>;
}

export interface A2AAgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  extensions?: A2AAgentExtension[];
  extendedAgentCard?: boolean;
  /** @deprecated Not part of the 1.0 AgentCapabilities message. */
  stateTransitionHistory?: boolean;
}

export interface A2AAgentExtension {
  uri: string;
  description?: string;
  required?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  params?: Record<string, any>;
}

export interface A2AAgentSkill {
  id: string;
  name: string;
  description: string;
  tags: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
  securityRequirements?: A2ASecurityRequirement[];
}

export interface A2AProvider {
  organization: string;
  url?: string;
}

/** @deprecated Legacy authentication block; use securitySchemes. */
export interface A2AAuthentication {
  schemes: Array<'Bearer' | 'Basic'>;
  credentials?: string;
}

// ============================================================
// Tasks, Messages, Parts (1.0 proto model)
// ============================================================

export type A2ATaskState =
  | 'TASK_STATE_UNSPECIFIED'
  | 'TASK_STATE_SUBMITTED'
  | 'TASK_STATE_WORKING'
  | 'TASK_STATE_COMPLETED'
  | 'TASK_STATE_FAILED'
  | 'TASK_STATE_CANCELED'
  | 'TASK_STATE_INPUT_REQUIRED'
  | 'TASK_STATE_REJECTED'
  | 'TASK_STATE_AUTH_REQUIRED';

export const A2A_TERMINAL_TASK_STATES: A2ATaskState[] = [
  'TASK_STATE_COMPLETED',
  'TASK_STATE_FAILED',
  'TASK_STATE_CANCELED',
  'TASK_STATE_REJECTED',
];

export interface A2ATaskStatus {
  state: A2ATaskState;
  message?: A2AMessage;
  /** ISO 8601 timestamp */
  timestamp?: string;
}

export interface A2ATask {
  id: string;
  contextId?: string;
  status: A2ATaskStatus;
  artifacts?: A2AArtifact[];
  history?: A2AMessage[];
  metadata?: Record<string, unknown>;
}

export interface A2AArtifact {
  artifactId: string;
  name?: string;
  description?: string;
  parts: A2APart[];
  metadata?: Record<string, unknown>;
  extensions?: string[];
}

export type A2ARole = 'ROLE_UNSPECIFIED' | 'ROLE_USER' | 'ROLE_AGENT';

export interface A2AMessage {
  /** Unique identifier of the message (required in 1.0) */
  messageId: string;
  role: A2ARole;
  parts: A2APart[];
  contextId?: string;
  taskId?: string;
  referenceTaskIds?: string[];
  extensions?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * A Part is a oneof: exactly one of text / raw / url / data is set.
 * There is no `type` or `kind` discriminator in A2A 1.0.
 */
export interface A2APart {
  text?: string;
  /** Base64-encoded file bytes */
  raw?: string;
  /** URL pointing to the file content */
  url?: string;
  /** Arbitrary structured data as a JSON value */
  data?: unknown;
  mediaType?: string;
  filename?: string;
  metadata?: Record<string, unknown>;
}

// ============================================================
// JSON-RPC 2.0 binding (spec section 9)
// ============================================================

export interface A2AJsonRpcRequest<TParams = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: TParams;
}

export interface A2AJsonRpcSuccess<TResult = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  result: TResult;
}

export interface A2AJsonRpcErrorObject {
  code: number;
  message: string;
  data?: unknown;
}

export interface A2AJsonRpcFailure {
  jsonrpc: '2.0';
  id: string | number | null;
  error: A2AJsonRpcErrorObject;
}

export type A2AJsonRpcResponse<TResult = unknown> =
  | A2AJsonRpcSuccess<TResult>
  | A2AJsonRpcFailure;

/** JSON-RPC method names of the A2A 1.0 JSON-RPC binding (spec 9.4). */
export const A2A_METHODS = {
  sendMessage: 'SendMessage',
  sendStreamingMessage: 'SendStreamingMessage',
  getTask: 'GetTask',
  listTasks: 'ListTasks',
  cancelTask: 'CancelTask',
  subscribeToTask: 'SubscribeToTask',
  createTaskPushNotificationConfig: 'CreateTaskPushNotificationConfig',
  getTaskPushNotificationConfig: 'GetTaskPushNotificationConfig',
  listTaskPushNotificationConfigs: 'ListTaskPushNotificationConfigs',
  deleteTaskPushNotificationConfig: 'DeleteTaskPushNotificationConfig',
  getExtendedAgentCard: 'GetExtendedAgentCard',
} as const;

// ============================================================
// Operation params and results (proto messages, JSON form)
// ============================================================

export interface A2ASendMessageConfiguration {
  acceptedOutputModes?: string[];
  taskPushNotificationConfig?: A2ATaskPushNotificationConfig;
  historyLength?: number;
  returnImmediately?: boolean;
}

export interface A2ASendMessageRequest {
  tenant?: string;
  message: A2AMessage;
  configuration?: A2ASendMessageConfiguration;
  metadata?: Record<string, unknown>;
}

/** SendMessage result: exactly one of task / message. */
export interface A2ASendMessageResponse {
  task?: A2ATask;
  message?: A2AMessage;
}

export interface A2AGetTaskRequest {
  tenant?: string;
  id: string;
  historyLength?: number;
}

export interface A2AListTasksRequest {
  tenant?: string;
  contextId?: string;
  status?: A2ATaskState;
  pageSize?: number;
  pageToken?: string;
  historyLength?: number;
  includeArtifacts?: boolean;
}

export interface A2AListTasksResponse {
  tasks: A2ATask[];
  totalSize?: number;
  nextPageToken?: string;
}

export interface A2ACancelTaskRequest {
  tenant?: string;
  id: string;
  metadata?: Record<string, unknown>;
}

export interface A2ATaskPushNotificationConfig {
  taskId?: string;
  id?: string;
  url?: string;
  authenticationInfo?: { schemes?: string[]; credentials?: string };
  [key: string]: unknown;
}

/** StreamResponse event: exactly one payload field is set. */
export interface A2AStreamResponse {
  task?: A2ATask;
  message?: A2AMessage;
  statusUpdate?: A2ATaskStatusUpdateEvent;
  artifactUpdate?: A2ATaskArtifactUpdateEvent;
}

export interface A2ATaskStatusUpdateEvent {
  taskId: string;
  contextId: string;
  status: A2ATaskStatus;
  metadata?: Record<string, unknown>;
}

export interface A2ATaskArtifactUpdateEvent {
  taskId: string;
  contextId: string;
  artifact: A2AArtifact;
  append?: boolean;
  lastChunk?: boolean;
  metadata?: Record<string, unknown>;
}

// ============================================================
// Legacy 0.2.x / 0.3.0 shapes (deprecated, adapter input/output)
// ============================================================

/** @deprecated Pre-1.0 task status strings. Use A2ATaskState. */
export type A2ALegacyTaskStatus =
  | 'pending'
  | 'submitted'
  | 'working'
  | 'completed'
  | 'failed'
  | 'canceled';

/** @deprecated Pre-1.0 task shape. Use A2ATask. */
export interface A2ALegacyTask {
  id: string;
  status: A2ALegacyTaskStatus;
  history?: A2ALegacyMessage[];
}

/** @deprecated Pre-1.0 message shape (no messageId, lowercase role). Use A2AMessage. */
export interface A2ALegacyMessage {
  role: 'user' | 'agent';
  parts: A2ALegacyPart[];
  metadata?: Record<string, unknown>;
}

/** @deprecated Pre-1.0 part shape with a `type` discriminator. Use A2APart. */
export interface A2ALegacyPart {
  type: 'text' | 'file' | 'image' | 'data' | 'tool-use' | 'tool-result';
  text?: string;
  file?: A2ALegacyFilePart;
  image?: A2ALegacyFilePart;
  data?: Record<string, unknown>;
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
  isError?: boolean;
  content?: string;
}

export interface A2ALegacyFilePart {
  mimeType?: string;
  uri?: string;
  name?: string;
  bytes?: string;
}

/** @deprecated Alias of A2ALegacyFilePart (pre-1.0 name). */
export type A2AFilePart = A2ALegacyFilePart;
/** @deprecated Alias of A2ALegacyFilePart (pre-1.0 name). */
export type A2AImagePart = A2ALegacyFilePart;

/** @deprecated Pre-1.0 request shape for the removed ad hoc endpoints. */
export interface A2ASendTaskRequest {
  id: string;
  message: A2ALegacyMessage;
  metadata?: Record<string, unknown>;
}

/** @deprecated Pre-1.0 response shape. Use A2ASendMessageResponse. */
export interface A2ASendTaskResponse {
  id: string;
  status: A2ALegacyTaskStatus;
}

/** @deprecated Pre-1.0 request shape. Use A2AGetTaskRequest (same fields). */
export interface A2AGetTaskRequestLegacy {
  id: string;
}

/** @deprecated Pre-1.0 response shape. Use A2ATask. */
export interface A2AGetTaskResponse {
  id: string;
  status: A2ALegacyTaskStatus;
  message?: A2ALegacyMessage;
  metadata?: Record<string, unknown>;
}

/** @deprecated Pre-1.0 request shape. Use A2ACancelTaskRequest (same fields). */
export interface A2ACancelTaskRequestLegacy {
  id: string;
}

// ============================================================
// Compliance Types
// ============================================================

export type ComplianceSeverity = 'critical' | 'warning' | 'info';

export interface ComplianceRule {
  id: string;
  name: string;
  description: string;
  severity: ComplianceSeverity;
  check: (agentCard: A2AAgentCard) => ComplianceResult;
}

export interface ComplianceResult {
  passed: boolean;
  ruleId: string;
  message: string;
  severity: ComplianceSeverity;
  details?: Record<string, unknown>;
}

export interface ComplianceReport {
  timestamp: Date;
  agentId: string;
  agentName: string;
  agentCardUrl: string;
  results: ComplianceResult[];
  passedCount: number;
  failedCount: number;
  warningCount: number;
}
