// A2A Protocol Types - Based on https://a2a-protocol.org/latest/

export interface A2AClientConfig {
  id?: string;
  name: string;
  agentCardUrl: string;
  auth?: A2AAuthConfig;
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

// Agent Card Types
export interface A2AAgentCard {
  name: string;
  description: string;
  url: string;
  version: string;
  /** A2A protocol revision the agent implements (e.g. "0.3.0") */
  protocolVersion?: string;
  capabilities: A2AAgentCapabilities;
  /** Modern OpenAPI-style security (current A2A spec) */
  securitySchemes?: Record<string, A2ASecurityScheme>;
  security?: Array<Record<string, string[]>>;
  /** Deprecated — superseded by securitySchemes/security */
  authentication?: A2AAuthentication;
  /** Transport selection (A2A v0.2.x+) */
  preferredTransport?: string;
  additionalInterfaces?: A2AAgentInterface[];
  supportedInterfaces?: A2AAgentInterface[];
  /** JWS signatures over the canonical agent card (AgentCardSignature) */
  signatures?: A2AAgentCardSignature[];
  supportsAuthenticatedExtendedCard?: boolean;
  iconUrl?: string;
  documentationUrl?: string;
  provider?: A2AProvider;
  supportedModels?: string[];
  tags?: string[];
}

export interface A2AAgentInterface {
  url: string;
  /** v0.2.x/v0.3.x use `transport`; newer drafts use `protocolBinding` */
  transport?: 'JSONRPC' | 'GRPC' | 'HTTP+JSON' | string;
  protocolBinding?: string;
  protocolVersion?: string;
}

export interface A2ASecurityScheme {
  type: 'apiKey' | 'http' | 'oauth2' | 'openIdConnect' | 'mutualTLS' | string;
  scheme?: string;
  in?: 'header' | 'query' | 'cookie';
  name?: string;
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

export interface A2AAgentExtension {
  uri: string;
  description?: string;
  required?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  params?: Record<string, any>;
}

export interface A2AAgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
  extensions?: A2AAgentExtension[];
  extendedAgentCard?: boolean;
}

export interface A2AAuthentication {
  schemes: Array<'Bearer' | 'Basic'>;
  credentials?: string;
}

export interface A2AProvider {
  organization: string;
  url: string;
}

// Task Types
export interface A2ATask {
  id: string;
  status: A2ATaskStatus;
  history?: A2AMessage[];
}

export type A2ATaskStatus = 'pending' | 'submitted' | 'working' | 'completed' | 'failed' | 'canceled';

export interface A2AMessage {
  role: 'user' | 'agent';
  parts: A2APart[];
  metadata?: Record<string, unknown>;
}

export interface A2APart {
  type: 'text' | 'file' | 'image' | 'data' | 'tool-use' | 'tool-result';
  text?: string;
  file?: A2AFilePart;
  image?: A2AImagePart;
  data?: Record<string, unknown>;
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
  isError?: boolean;
  content?: string;
}

export interface A2AFilePart {
  mimeType?: string;
  uri?: string;
  name?: string;
  bytes?: string;
}

export interface A2AImagePart {
  mimeType?: string;
  uri?: string;
  bytes?: string;
}

// Request/Response Types
export interface A2ASendTaskRequest {
  id: string;
  message: A2AMessage;
  metadata?: Record<string, unknown>;
}

export interface A2ASendTaskResponse {
  id: string;
  status: A2ATaskStatus;
}

export interface A2AGetTaskRequest {
  id: string;
}

export interface A2AGetTaskResponse {
  id: string;
  status: A2ATaskStatus;
  message?: A2AMessage;
  metadata?: Record<string, unknown>;
}

export interface A2ACancelTaskRequest {
  id: string;
}

export interface A2ATaskPushNotificationConfig {
  url: string;
  token?: string;
}

// Compliance Types
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
