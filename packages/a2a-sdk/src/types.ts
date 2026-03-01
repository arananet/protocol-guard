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
  capabilities: A2AAgentCapabilities;
  authentication: A2AAuthentication;
  provider?: A2AProvider;
  supportedModels?: string[];
  tags?: string[];
}

export interface A2AAgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
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
