// MCP Protocol Types - Based on https://modelcontextprotocol.io/docs/getting-started/intro

export interface MCPJsonRPC {
  jsonrpc: '2.0';
  id: string | number | null;
  method: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: MCPError;
}

export interface MCPError {
  code: number;
  message: string;
  data?: unknown;
}

// MCP Request/Response Types
export interface MCPInitializeRequest {
  protocolVersion: string;
  capabilities: MCPServerCapabilities;
  clientInfo: MCPClientInfo;
}

export interface MCPInitializeResponse {
  protocolVersion: string;
  capabilities: MCPServerCapabilities;
  serverInfo: MCPServerInfo;
}

export interface MCPServerCapabilities {
  tools?: MCPToolsCapability;
  resources?: MCPResourcesCapability;
  prompts?: MCPPromptsCapability;
  logging?: MCPLoggingCapability;
  progress?: boolean;
  roots?: MCPRootsCapability;
}

export interface MCPToolsCapability {
  listChanged?: boolean;
}

export interface MCPResourcesCapability {
  subscribe?: boolean;
  listChanged?: boolean;
}

export interface MCPPromptsCapability {
  listChanged?: boolean;
}

export interface MCPLoggingCapability {
  level?: string;
}

export interface MCPRootsCapability {
  listChanged?: boolean;
}

export interface MCPClientInfo {
  name: string;
  version: string;
}

export interface MCPServerInfo {
  name: string;
  version: string;
  capabilities?: MCPServerCapabilities;
}

// Tool Types
export interface MCPTool {
  name: string;
  description?: string;
  inputSchema: MCPJSONSchema;
}

export interface MCPToolCallRequest {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface MCPToolCallResponse {
  content: MCPToolContent[];
  isError?: boolean;
}

export interface MCPToolContent {
  type: 'text' | 'image' | 'resource';
  text?: string;
  mimeType?: string;
  data?: string;
  uri?: string;
}

// Resource Types
export interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface MCPResourceContents {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string;
}

// Prompt Types
export interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: MCPPromptArgument[];
}

export interface MCPPromptArgument {
  name: string;
  description?: string;
  required?: boolean;
  type?: string;
}

export interface MCPPromptMessage {
  role: 'user' | 'assistant';
  content: MCPToolContent;
}

// JSON Schema (simplified)
export interface MCPJSONSchema {
  type?: string;
  properties?: Record<string, unknown>;
  required?: string[];
  description?: string;
  additionalProperties?: boolean;
}

// Authentication Types
export interface MCPAuthConfig {
  type: 'none' | 'apiKey' | 'oauth';
  apiKey?: string;
  oauth?: MCPOAuthConfig;
}

export interface MCPOAuthConfig {
  clientId: string;
  clientSecret?: string;
  tokenEndpoint?: string;
  scopes?: string[];
}

// Server Configuration
export interface MCPServerConfig {
  id?: string;
  name: string;
  url: string;
  auth: MCPAuthConfig;
  capabilities?: MCPServerCapabilities;
}

// Compliance Types
export type ComplianceSeverity = 'critical' | 'warning' | 'info';

export interface ComplianceRule {
  id: string;
  name: string;
  description: string;
  severity: ComplianceSeverity;
  check: (server: MCPServerConfig, response: unknown) => ComplianceResult;
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
  serverId: string;
  serverName: string;
  protocolVersion: string;
  results: ComplianceResult[];
  passedCount: number;
  failedCount: number;
  warningCount: number;
}
