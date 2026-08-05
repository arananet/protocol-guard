import { NextRequest, NextResponse } from 'next/server';
import {
  MCP_DEPRECATED_VERSIONS,
  MCP_KNOWN_VERSIONS,
  MCP_LATEST_VERSION,
  MCP_LEGACY_VERSIONS,
  MCP_SPEC_URLS,
  buildBaseHeaders,
  cacheHintsOf,
  collectXMcpHeaderBindings,
  connectMCP,
  mcpCall,
  parseMCPResponse,
  resultTypeOf,
  type Json,
  type MCPConnection,
} from '@/lib/mcp';

/**
 * MCP Security Scanner — OWASP MCP Top 10 vulnerability analysis
 *
 * Implements checks inspired by:
 *  - OWASP MCP Top 10 (https://owasp.org/www-project-mcp-top-10/)
 *  - mcp-shield patterns (https://github.com/riseandignite/mcp-shield)
 *
 * Version-aware: the scanner speaks MCP 2026-07-28 (stateless, per-request
 * metadata) and falls back to the handshake era, then audits the
 * security-relevant surface each revision introduced.
 *
 * All analysis is stateless — nothing is stored.
 */

// ─── OWASP MCP Top 10 Definitions ───────────────────────────────────────────

const OWASP_MCP_TOP_10 = {
  MCP01: {
    id: 'MCP01',
    title: 'Token Mismanagement & Secret Exposure',
    description: 'Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol logs.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP01-2025-Token-Mismanagement-and-Secret-Exposure',
  },
  MCP02: {
    id: 'MCP02',
    title: 'Privilege Escalation via Scope Creep',
    description: 'Loosely defined permissions granting agents excessive capabilities beyond their intended role.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep',
  },
  MCP03: {
    id: 'MCP03',
    title: 'Tool Poisoning',
    description: 'Adversary compromises tools or their descriptions to inject malicious instructions.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning',
  },
  MCP04: {
    id: 'MCP04',
    title: 'Software Supply Chain Attacks',
    description: 'Compromised dependencies altering agent behavior or introducing backdoors.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP04-2025%E2%80%93Software-Supply-Chain-Attacks&Dependency-Tampering',
  },
  MCP05: {
    id: 'MCP05',
    title: 'Command Injection & Execution',
    description: 'AI agent constructs and executes system commands using untrusted input without sanitization.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP05-2025%E2%80%93Command-Injection&Execution',
  },
  MCP06: {
    id: 'MCP06',
    title: 'Intent Flow Subversion',
    description: 'Malicious instructions embedded in context hijack the intent flow away from the user\'s goal.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP06-2025%E2%80%93Intent-Flow-Subversion',
  },
  MCP07: {
    id: 'MCP07',
    title: 'Insufficient Authentication & Authorization',
    description: 'MCP servers fail to properly verify identities or enforce access controls.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP07-2025%E2%80%93Insufficient-Authentication&Authorization',
  },
  MCP08: {
    id: 'MCP08',
    title: 'Lack of Audit and Telemetry',
    description: 'Limited telemetry impedes investigation and incident response.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP08-2025%E2%80%93Lack-of-Audit-and-Telemetry',
  },
  MCP09: {
    id: 'MCP09',
    title: 'Shadow MCP Servers',
    description: 'Unapproved MCP instances operating outside security governance.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP09-2025%E2%80%93Shadow-MCP-Servers',
  },
  MCP10: {
    id: 'MCP10',
    title: 'Context Injection & Over-Sharing',
    description: 'Sensitive information leaks across sessions or agents through shared context windows.',
    url: 'https://owasp.org/www-project-mcp-top-10/2025/MCP10-2025%E2%80%93ContextInjection&OverSharing',
  },
};

// ─── Detection Patterns (inspired by mcp-shield) ────────────────────────────

const HIDDEN_INSTRUCTION_PATTERNS = [
  /<instructions>/i, /<\/instructions>/i,
  /<system>/i, /<\/system>/i,
  /<IMPORTANT>/i, /<\/IMPORTANT>/i,
  /<secret>/i, /<\/secret>/i,
  /do not mention/i, /do not tell/i, /do not inform/i,
  /never inform the user/i, /never mention/i,
  /don't tell the user/i, /don't mention/i,
  /hide this from/i, /keep this hidden/i,
  /before using this tool/i,
  /this is very important/i,
  /the application will crash/i,
];

const SENSITIVE_FILE_PATTERNS = [
  /\.ssh/i, /id_rsa/i, /id_ed25519/i,
  /\.env/i, /config\.json/i, /\.aws/i,
  /credentials/i, /\.gnupg/i, /\.kube/i,
  /wallet\.dat/i, /keychain/i,
  /passwd/i, /shadow/i,
  /\.pem$/i, /\.key$/i, /private.*key/i,
];

const SHADOWING_PATTERNS = [
  /when this tool is available/i,
  /modify the behavior of/i,
  /override.*behavior/i,
  /side effect on/i,
  /must send all.*to/i,
  /change the recipient/i,
  /redirect.*to/i,
  /proxy.*number/i,
  /must.*use.*instead/i,
];

const EXFILTRATION_PARAM_NAMES = [
  'notes', 'metadata', 'feedback', 'debug', 'extra', 'telemetry',
  'analytics', 'tracking', 'callback', 'webhook', 'report_url',
];

const COMMAND_INJECTION_PATTERNS = [
  /exec\s*\(/i, /eval\s*\(/i, /system\s*\(/i,
  /child_process/i, /subprocess/i, /os\.system/i,
  /shell_exec/i, /popen/i, /spawn/i,
  /\$\(.*\)/i, /`.*`/,
  /rm\s+-rf/i, /chmod\s+777/i,
  /curl.*\|.*sh/i, /wget.*\|.*bash/i,
];

const SECRET_PATTERNS = [
  /api[_-]?key\s*[:=]\s*["'][^"']+["']/i,
  /password\s*[:=]\s*["'][^"']+["']/i,
  /secret\s*[:=]\s*["'][^"']+["']/i,
  /token\s*[:=]\s*["'][^"']+["']/i,
  /bearer\s+[a-zA-Z0-9_.+-]+/i,
  /sk-[a-zA-Z0-9]{20,}/,
  /ghp_[a-zA-Z0-9]{36}/,
  /xox[bporas]-[a-zA-Z0-9-]+/,
];

// ─── MCP Server Security Standard (MSSS) v0.1 Reference ────────────────────
// https://github.com/mcp-security-standard/mcp-server-security-standard

const MSSS_CONTROLS = {
  'MCP-INPUT-01': { id: 'MCP-INPUT-01', level: 'L1', title: 'JSON Schema Validation', description: 'All tool arguments must be validated against a strict JSON Schema before execution.' },
  'MCP-INPUT-02': { id: 'MCP-INPUT-02', level: 'L2', title: 'Input Bounds Enforcement', description: 'Explicit bounds (maxLength, maxItems, maxProperties) must be defined on all input parameters.' },
  'MCP-NET-01':   { id: 'MCP-NET-01',   level: 'L1', title: 'URL Validation / SSRF Prevention', description: 'URL parameters must be validated against an allowlist or block private IP ranges and metadata endpoints.' },
  'MCP-FS-01':    { id: 'MCP-FS-01',    level: 'L1', title: 'Path Allowlisting', description: 'File/path parameters must be restricted to an allowlist to prevent unauthorized access.' },
  'MCP-FS-02':    { id: 'MCP-FS-02',    level: 'L1', title: 'Symlink Resolution', description: 'Servers must resolve symlinks and verify the canonical path is within the allowlist.' },
  'MCP-EXEC-01':  { id: 'MCP-EXEC-01',  level: 'L1', title: 'No Shell Execution', description: 'Tools must not use shell=true or equivalent; use direct process invocation instead.' },
  'MCP-EXEC-03':  { id: 'MCP-EXEC-03',  level: 'L2', title: 'Argument Separation', description: 'Command arguments must be passed as arrays, never interpolated into shell strings.' },
  'MCP-NET-03':   { id: 'MCP-NET-03',   level: 'L2', title: 'TLS 1.2+ Enforcement', description: 'All remote connections must use TLS 1.2 or higher.' },
  'MCP-LOG-01':   { id: 'MCP-LOG-01',   level: 'L3', title: 'Audit Logging', description: 'All tool invocations must be logged with sufficient context for forensic investigation.' },
  'MCP-LOG-02':   { id: 'MCP-LOG-02',   level: 'L1', title: 'Secret Redaction', description: 'Secrets and credentials must be automatically redacted from logs and responses.' },
  'MCP-AUTHZ-01': { id: 'MCP-AUTHZ-01', level: 'L3', title: 'OAuth 2.1 Delegation', description: 'Tools requiring elevated access should use OAuth 2.1 delegation flows.' },
  'MCP-AUTHZ-03': { id: 'MCP-AUTHZ-03', level: 'L3', title: 'Least Privilege', description: 'Each tool should request only the minimum permissions required for its function.' },
};

// ─── MSSS Detection Pattern Arrays ──────────────────────────────────────────

// URL-like parameter names (SSRF / MCP-NET-01)
const URL_PARAM_NAMES = [
  'url', 'uri', 'endpoint', 'link', 'href', 'target', 'host',
  'base_url', 'baseurl', 'webhook', 'webhook_url', 'callback',
  'callback_url', 'redirect', 'redirect_url', 'fetch_url', 'source_url',
];

// Path-like parameter names (path traversal / MCP-FS-01)
const PATH_PARAM_NAMES = [
  'path', 'file', 'filepath', 'file_path', 'filename', 'file_name',
  'directory', 'dir', 'folder', 'dest', 'destination', 'src', 'source',
  'target_path', 'output_path', 'input_path', 'base_path', 'root_path',
];

// Symlink-related patterns in descriptions (MCP-FS-02)
const SYMLINK_PATTERNS = [
  /symlink/i, /symbolic\s+link/i, /readlink/i,
  /ln\s+-s/i, /os\.readlink/i, /followlinks/i,
];

// Command argument parameter names (argument injection / MCP-EXEC-03)
const ARG_INJECTION_PARAM_NAMES = [
  'cmd', 'command', 'args', 'argv', 'shell', 'shell_cmd', 'shell_command',
  'exec', 'execute', 'run', 'script', 'process', 'subprocess', 'invoke',
  'cli_args', 'params', 'flags', 'options',
];

// ─── MCP Protocol Version Awareness ─────────────────────────────────────────
// The scanner negotiates the latest spec revision and downgrades gracefully.
// Security-relevant milestones:
//   2024-11-05 — original revision, NO authorization framework
//   2025-03-26 — OAuth 2.1 introduced, but WITHOUT Resource Indicators (RFC 8707)
//   2025-06-18 — MCP servers classified as OAuth Resource Servers, Resource
//                Indicators (RFC 8707) + Protected Resource Metadata (RFC 9728)
//                REQUIRED, dedicated security best-practices page, structured
//                tool output, tool annotations, elicitation
//   2025-11-25 — further auth + transport hardening; last handshake-era revision
//   2026-07-28 — stateless protocol: no initialize handshake and no
//                Mcp-Session-Id, mandatory server/discover, mirrored
//                Mcp-Method/Mcp-Name headers with server-side validation
//                (HeaderMismatch -32020), required ttlMs/cacheScope hints,
//                RFC 9207 issuer validation, Client ID Metadata Documents
//                superseding Dynamic Client Registration, and Roots/Sampling/
//                Logging deprecated
//
// Version constants live in @/lib/mcp so every MCP route grades against the
// same revision list.

/** Sensitive header names that must never be fed from tool arguments. */
const SENSITIVE_HEADER_NAMES = [
  'authorization', 'cookie', 'set-cookie', 'proxy-authorization',
  'x-api-key', 'apikey', 'api-key', 'x-auth-token', 'auth-token',
  'x-access-token', 'access-token', 'x-csrf-token', 'x-forwarded-for',
  'x-forwarded-host', 'host',
];

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  owaspId: string;
  owaspTitle: string;
  owaspUrl: string;
  /** MSSS control ID (e.g. MCP-INPUT-01) when this finding maps to the MCP Server Security Standard */
  msssId?: string;
  /** MSSS compliance level (L1–L4) of the failing control */
  msssLevel?: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  toolName?: string;
  evidence?: string;
}

interface MCPToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string }>;
    required?: string[];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    additionalProperties?: any;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  outputSchema?: any;
  annotations?: MCPToolAnnotations;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  _meta?: Record<string, any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

interface MCPResource {
  uri?: string;
  name?: string;
  description?: string;
  mimeType?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  _meta?: Record<string, any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

interface MCPPrompt {
  name?: string;
  description?: string;
  arguments?: Array<{ name?: string; description?: string; required?: boolean }>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

// ─── Analysis Functions ──────────────────────────────────────────────────────

function analyzeToolForHiddenInstructions(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const desc = tool.description || '';

  for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      findings.push({
        owaspId: 'MCP03',
        owaspTitle: OWASP_MCP_TOP_10.MCP03.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP03.url,
        severity: 'critical',
        category: 'Tool Poisoning',
        title: 'Hidden instructions detected in tool description',
        description: `The tool "${tool.name}" contains hidden instruction patterns that could manipulate AI behavior.`,
        toolName: tool.name,
        evidence: match[0],
      });
      break; // One finding per tool for this category
    }
  }

  return findings;
}

function analyzeToolForSensitiveFileAccess(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const desc = tool.description || '';

  const found: string[] = [];
  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    const match = desc.match(pattern);
    if (match && !found.includes(match[0].toLowerCase())) {
      found.push(match[0].toLowerCase());
    }
  }

  if (found.length > 0) {
    findings.push({
      owaspId: 'MCP01',
      owaspTitle: OWASP_MCP_TOP_10.MCP01.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP01.url,
      severity: 'high',
      category: 'Secret Exposure',
      title: 'Sensitive file access in tool description',
      description: `The tool "${tool.name}" references sensitive files/paths that could expose credentials.`,
      toolName: tool.name,
      evidence: found.join(', '),
    });
  }

  return findings;
}

function analyzeToolForShadowing(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const desc = tool.description || '';

  for (const pattern of SHADOWING_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      findings.push({
        owaspId: 'MCP06',
        owaspTitle: OWASP_MCP_TOP_10.MCP06.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP06.url,
        severity: 'critical',
        category: 'Intent Subversion',
        title: 'Tool shadowing / cross-origin behavior modification detected',
        description: `The tool "${tool.name}" attempts to modify the behavior of other tools, which is a form of intent flow subversion.`,
        toolName: tool.name,
        evidence: match[0],
      });
      break;
    }
  }

  return findings;
}

function analyzeToolForExfiltration(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const params = tool.inputSchema?.properties || {};

  const suspicious = Object.keys(params).filter(name =>
    EXFILTRATION_PARAM_NAMES.some(p => name.toLowerCase().includes(p))
  );

  if (suspicious.length > 0) {
    findings.push({
      owaspId: 'MCP10',
      owaspTitle: OWASP_MCP_TOP_10.MCP10.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP10.url,
      severity: 'medium',
      category: 'Data Exfiltration',
      title: 'Suspicious parameters that could be used for data exfiltration',
      description: `The tool "${tool.name}" has parameters that could exfiltrate data: ${suspicious.join(', ')}.`,
      toolName: tool.name,
      evidence: suspicious.join(', '),
    });
  }

  // Check for passthrough/object params that accept arbitrary data
  for (const [name, schema] of Object.entries(params)) {
    if (schema.type === 'object' && !suspicious.includes(name)) {
      findings.push({
        owaspId: 'MCP10',
        owaspTitle: OWASP_MCP_TOP_10.MCP10.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP10.url,
        severity: 'low',
        category: 'Data Exfiltration',
        title: 'Open object parameter could accept arbitrary data',
        description: `The tool "${tool.name}" has an object parameter "${name}" that could accept arbitrary data.`,
        toolName: tool.name,
        evidence: `${name}: object`,
      });
    }
  }

  return findings;
}

function analyzeToolForCommandInjection(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const desc = tool.description || '';

  for (const pattern of COMMAND_INJECTION_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      findings.push({
        owaspId: 'MCP05',
        owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
        severity: 'high',
        category: 'Command Injection',
        title: 'Command execution patterns detected in tool description',
        description: `The tool "${tool.name}" description contains patterns suggesting command execution.`,
        toolName: tool.name,
        evidence: match[0],
      });
      break;
    }
  }

  return findings;
}

function analyzeToolForSecretLeakage(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const desc = tool.description || '';

  for (const pattern of SECRET_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      // Redact the actual secret
      const redacted = match[0].substring(0, 10) + '...[REDACTED]';
      findings.push({
        owaspId: 'MCP01',
        owaspTitle: OWASP_MCP_TOP_10.MCP01.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP01.url,
        severity: 'critical',
        category: 'Secret Exposure',
        title: 'Potential secret/credential found in tool description',
        description: `The tool "${tool.name}" description may contain embedded credentials or tokens.`,
        toolName: tool.name,
        evidence: redacted,
      });
      break;
    }
  }

  return findings;
}

function analyzeServerCapabilities(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  capabilities: any,
  tools: MCPTool[],
  url: string
): Finding[] {
  const findings: Finding[] = [];

  // MCP02: Scope Creep — too many capabilities without restriction
  if (tools.length > 20) {
    findings.push({
      owaspId: 'MCP02',
      owaspTitle: OWASP_MCP_TOP_10.MCP02.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP02.url,
      severity: 'medium',
      category: 'Scope Creep',
      title: `Server exposes ${tools.length} tools — potential scope creep`,
      description: 'A high number of tools increases the attack surface. Consider implementing role-based tool access.',
    });
  }

  // MCP07: Check if server uses plain HTTP (not HTTPS)
  if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
    findings.push({
      owaspId: 'MCP07',
      owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
      severity: 'high',
      category: 'Insecure Transport',
      title: 'Server uses HTTP instead of HTTPS',
      description: 'The MCP server uses unencrypted HTTP. Credentials and data are transmitted in plaintext.',
      evidence: url,
    });
  }

  // MCP08: Check for absence of logging/audit capability
  if (!capabilities || Object.keys(capabilities).length === 0) {
    findings.push({
      owaspId: 'MCP08',
      owaspTitle: OWASP_MCP_TOP_10.MCP08.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP08.url,
      severity: 'medium',
      category: 'Audit',
      title: 'Server declares no capabilities — missing access control structure',
      description: 'The server returned an empty capabilities object. This indicates missing audit, logging, and access control features.',
    });
  } else {
    const capKeys = Object.keys(capabilities).map(k => k.toLowerCase());
    const hasLogging = capKeys.some(k => k.includes('log') || k.includes('audit') || k.includes('telemetry') || k.includes('monitor'));
    if (!hasLogging) {
      findings.push({
        owaspId: 'MCP08',
        owaspTitle: OWASP_MCP_TOP_10.MCP08.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP08.url,
        severity: 'info',
        category: 'Audit',
        title: 'No logging or audit capability declared',
        description: 'The server capabilities do not include any logging, audit, or telemetry capability. This limits incident response and forensic investigation.',
        evidence: `Declared capabilities: ${capKeys.join(', ')}`,
      });
    }
  }

  return findings;
}

/**
 * Analyze server `instructions` field from init response for hidden instructions,
 * context injection, and information leakage.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function analyzeInstructionsField(initResult: any): Finding[] {
  const findings: Finding[] = [];
  const instructions = initResult?.instructions;
  if (!instructions || typeof instructions !== 'string') return findings;

  // MCP10: Instructions that expose internal tool details leak context
  if (instructions.length > 200) {
    findings.push({
      owaspId: 'MCP10',
      owaspTitle: OWASP_MCP_TOP_10.MCP10.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP10.url,
      severity: 'low',
      category: 'Context Over-Sharing',
      title: 'Verbose server instructions may leak internal context',
      description: `Server instructions field is ${instructions.length} characters long and may expose internal tool details, architecture, or operational context that could assist an attacker.`,
      evidence: instructions.substring(0, 200) + (instructions.length > 200 ? '...' : ''),
    });
  }

  // MCP03/MCP06: Check instructions for hidden instruction patterns
  for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
    const match = instructions.match(pattern);
    if (match) {
      findings.push({
        owaspId: 'MCP03',
        owaspTitle: OWASP_MCP_TOP_10.MCP03.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP03.url,
        severity: 'critical',
        category: 'Tool Poisoning',
        title: 'Hidden instruction pattern detected in server instructions',
        description: 'The server instructions field contains patterns that could manipulate AI agent behavior.',
        evidence: match[0],
      });
      break;
    }
  }

  // MCP06: Check instructions for shadowing patterns
  for (const pattern of SHADOWING_PATTERNS) {
    const match = instructions.match(pattern);
    if (match) {
      findings.push({
        owaspId: 'MCP06',
        owaspTitle: OWASP_MCP_TOP_10.MCP06.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP06.url,
        severity: 'high',
        category: 'Intent Subversion',
        title: 'Intent subversion pattern detected in server instructions',
        description: 'The server instructions field contains patterns that attempt to redirect or modify expected behavior.',
        evidence: match[0],
      });
      break;
    }
  }

  // MCP01: Check instructions for embedded secrets
  for (const pattern of SECRET_PATTERNS) {
    const match = instructions.match(pattern);
    if (match) {
      const redacted = match[0].substring(0, 10) + '...[REDACTED]';
      findings.push({
        owaspId: 'MCP01',
        owaspTitle: OWASP_MCP_TOP_10.MCP01.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP01.url,
        severity: 'critical',
        category: 'Secret Exposure',
        title: 'Potential secret found in server instructions',
        description: 'The server instructions field may contain embedded credentials or tokens.',
        evidence: redacted,
      });
      break;
    }
  }

  return findings;
}

/**
 * Check if the server accepted the connection without authentication.
 * A server that responds successfully to unauthenticated requests is a risk.
 */
function analyzeAuthenticationPosture(authType: string | undefined, connectionSucceeded: boolean): Finding[] {
  const findings: Finding[] = [];

  if ((!authType || authType === 'none') && connectionSucceeded) {
    findings.push({
      owaspId: 'MCP07',
      owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
      severity: 'medium',
      category: 'Authentication',
      title: 'Server accepts unauthenticated connections',
      description: 'The MCP server responded successfully without any authentication. Any client can connect and invoke tools. Consider requiring authentication to prevent unauthorized access.',
      evidence: 'Connection succeeded with authType: none',
    });
  }

  return findings;
}

/**
 * Detect framework and version information leakage from server metadata and tool schemas.
 */
function analyzeInformationLeakage(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  initResult: any,
  tools: MCPTool[]
): Finding[] {
  const findings: Finding[] = [];
  const serverInfo = initResult?.serverInfo;

  // MCP04: Server version disclosure
  if (serverInfo?.version) {
    findings.push({
      owaspId: 'MCP04',
      owaspTitle: OWASP_MCP_TOP_10.MCP04.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP04.url,
      severity: 'info',
      category: 'Information Disclosure',
      title: 'Server version exposed in serverInfo',
      description: `The server discloses its version (${serverInfo.version}), which may help attackers identify known vulnerabilities for that specific version.`,
      evidence: `${serverInfo.name || 'unknown'} v${serverInfo.version}`,
    });
  }

  // MCP04: Framework leakage in tool metadata (_meta, x-fastmcp, etc.)
  const frameworkHints: string[] = [];
  for (const tool of tools) {
    const toolStr = JSON.stringify(tool);
    if (toolStr.includes('_fastmcp') || toolStr.includes('fastmcp')) frameworkHints.push('FastMCP');
    if (toolStr.includes('langchain')) frameworkHints.push('LangChain');
    if (toolStr.includes('llamaindex') || toolStr.includes('llama_index')) frameworkHints.push('LlamaIndex');
    if (toolStr.includes('autogen')) frameworkHints.push('AutoGen');
    if (toolStr.includes('crewai')) frameworkHints.push('CrewAI');
    if (toolStr.includes('semantic_kernel') || toolStr.includes('semantickernel')) frameworkHints.push('Semantic Kernel');
  }

  const uniqueFrameworks = [...new Set(frameworkHints)];
  if (uniqueFrameworks.length > 0) {
    findings.push({
      owaspId: 'MCP04',
      owaspTitle: OWASP_MCP_TOP_10.MCP04.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP04.url,
      severity: 'low',
      category: 'Information Disclosure',
      title: 'Framework fingerprint detected in tool metadata',
      description: `Tool metadata exposes the underlying framework (${uniqueFrameworks.join(', ')}). Attackers can use this to target framework-specific vulnerabilities.`,
      evidence: uniqueFrameworks.join(', '),
    });
  }

  return findings;
}

/**
 * Analyze HTTP response headers from the MCP server for missing security headers.
 */
function analyzeResponseHeaders(headers: Headers, url: string): Finding[] {
  const findings: Finding[] = [];

  // Only check for HTTPS servers (HTTP already gets flagged separately)
  if (!url.startsWith('https://')) return findings;

  const importantHeaders: Array<{ name: string; severity: Severity; title: string; desc: string }> = [
    {
      name: 'strict-transport-security',
      severity: 'medium',
      title: 'Missing Strict-Transport-Security (HSTS) header',
      desc: 'Without HSTS, connections may be downgraded to HTTP. Add Strict-Transport-Security header.',
    },
    {
      name: 'x-content-type-options',
      severity: 'low',
      title: 'Missing X-Content-Type-Options header',
      desc: 'Without X-Content-Type-Options: nosniff, responses could be MIME-sniffed by browsers.',
    },
  ];

  for (const h of importantHeaders) {
    if (!headers.get(h.name)) {
      findings.push({
        owaspId: 'MCP09',
        owaspTitle: OWASP_MCP_TOP_10.MCP09.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP09.url,
        severity: h.severity,
        category: 'Response Headers',
        title: h.title,
        description: h.desc,
        evidence: `Header ${h.name} not present`,
      });
    }
  }

  // Check if server header leaks implementation details
  const serverHeader = headers.get('server');
  if (serverHeader) {
    findings.push({
      owaspId: 'MCP04',
      owaspTitle: OWASP_MCP_TOP_10.MCP04.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP04.url,
      severity: 'info',
      category: 'Information Disclosure',
      title: 'Server header exposes implementation details',
      description: 'The HTTP Server header reveals technology information that could help attackers fingerprint the deployment.',
      evidence: `Server: ${serverHeader}`,
    });
  }

  return findings;
}

function analyzeCrossToolViolations(tools: MCPTool[]): Finding[] {
  const findings: Finding[] = [];
  const toolNames = tools.map(t => t.name.toLowerCase());

  for (const tool of tools) {
    const desc = (tool.description || '').toLowerCase();
    // Check if this tool's description references other tools by name
    for (const otherName of toolNames) {
      if (otherName !== tool.name.toLowerCase() && desc.includes(otherName)) {
        findings.push({
          owaspId: 'MCP06',
          owaspTitle: OWASP_MCP_TOP_10.MCP06.title,
          owaspUrl: OWASP_MCP_TOP_10.MCP06.url,
          severity: 'high',
          category: 'Cross-Origin Violation',
          title: `Tool "${tool.name}" references another tool "${otherName}"`,
          description: `This tool's description mentions another tool, which could indicate cross-tool manipulation or intent flow subversion.`,
          toolName: tool.name,
          evidence: otherName,
        });
      }
    }
  }

  return findings;
}

// ─── MSSS Analysis Functions ─────────────────────────────────────────────────

/**
 * MCP-INPUT-01 (L1): JSON Schema Validation
 * Detects tools that lack a proper inputSchema or use loose schemas that permit
 * arbitrary extra properties, enabling schema-poisoning and injection attacks.
 */
function analyzeToolInputSchemaValidation(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];

  // No inputSchema at all → cannot validate anything
  if (!tool.inputSchema || typeof tool.inputSchema !== 'object') {
    findings.push({
      owaspId: 'MCP05',
      owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
      msssId: 'MCP-INPUT-01',
      msssLevel: 'L1',
      severity: 'high',
      category: 'Schema Validation',
      title: 'Tool missing inputSchema — no argument validation',
      description: `The tool "${tool.name}" does not declare an inputSchema. Without a schema, tool arguments cannot be validated, enabling injection attacks and type confusion.`,
      toolName: tool.name,
    });
    return findings;
  }

  const schema = tool.inputSchema;

  // Schema exists but additionalProperties is not explicitly false
  if (schema.additionalProperties !== false && schema.additionalProperties !== false) {
    // Only flag if the tool actually defines properties (implies it expects structured input)
    if (schema.properties && Object.keys(schema.properties).length > 0) {
      findings.push({
        owaspId: 'MCP05',
        owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
        msssId: 'MCP-INPUT-01',
        msssLevel: 'L1',
        severity: 'medium',
        category: 'Schema Validation',
        title: 'Tool schema allows additional properties',
        description: `The tool "${tool.name}" schema does not set additionalProperties: false, allowing unexpected extra fields to be passed to the tool, which may bypass validation.`,
        toolName: tool.name,
        evidence: 'additionalProperties not set to false',
      });
    }
  }

  return findings;
}

/**
 * MCP-INPUT-02 (L2): Input Bounds Enforcement
 * Detects tool schemas that lack explicit bounds (maxLength, maxItems, maximum, etc.)
 * on their parameters, enabling DoS via memory exhaustion or ReDoS.
 */
function analyzeToolInputBounds(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const schema = tool.inputSchema;
  if (!schema?.properties || typeof schema.properties !== 'object') return findings;

  const unboundedStrings: string[] = [];
  const unboundedArrays: string[] = [];

  for (const [name, prop] of Object.entries(schema.properties as Record<string, Record<string, unknown>>)) {
    if (prop.type === 'string' && prop.maxLength === undefined && prop.enum === undefined) {
      unboundedStrings.push(name);
    }
    if (prop.type === 'array' && prop.maxItems === undefined) {
      unboundedArrays.push(name);
    }
  }

  if (unboundedStrings.length > 0) {
    findings.push({
      owaspId: 'MCP05',
      owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
      msssId: 'MCP-INPUT-02',
      msssLevel: 'L2',
      severity: 'medium',
      category: 'Input Bounds',
      title: 'String parameters lack maxLength constraints',
      description: `The tool "${tool.name}" has string parameters without maxLength limits: ${unboundedStrings.join(', ')}. Unbounded strings can cause memory exhaustion or ReDoS attacks.`,
      toolName: tool.name,
      evidence: unboundedStrings.join(', '),
    });
  }

  if (unboundedArrays.length > 0) {
    findings.push({
      owaspId: 'MCP05',
      owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
      msssId: 'MCP-INPUT-02',
      msssLevel: 'L2',
      severity: 'low',
      category: 'Input Bounds',
      title: 'Array parameters lack maxItems constraints',
      description: `The tool "${tool.name}" has array parameters without maxItems limits: ${unboundedArrays.join(', ')}. Unbounded arrays can cause memory exhaustion attacks.`,
      toolName: tool.name,
      evidence: unboundedArrays.join(', '),
    });
  }

  return findings;
}

/**
 * MCP-NET-01 (L1): URL Validation / SSRF Prevention
 * Detects tools with URL-type parameters that lack a pattern or format constraint.
 * Without allowlist validation, these tools are potential SSRF vectors.
 */
function analyzeToolForSSRF(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const schema = tool.inputSchema;
  if (!schema?.properties || typeof schema.properties !== 'object') return findings;

  const ssrfParams: string[] = [];
  for (const [name, prop] of Object.entries(schema.properties as Record<string, Record<string, unknown>>)) {
    const lowerName = name.toLowerCase();
    const isUrlParam = URL_PARAM_NAMES.some(u => lowerName === u || lowerName.endsWith(`_${u}`) || lowerName.endsWith(u));
    if (isUrlParam && prop.type === 'string' && prop.pattern === undefined && prop.format === undefined && prop.enum === undefined) {
      ssrfParams.push(name);
    }
  }

  if (ssrfParams.length > 0) {
    findings.push({
      owaspId: 'MCP07',
      owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
      msssId: 'MCP-NET-01',
      msssLevel: 'L1',
      severity: 'high',
      category: 'SSRF',
      title: 'URL parameter without validation — potential SSRF vector',
      description: `The tool "${tool.name}" accepts URL-like parameter(s) without pattern or format constraints: ${ssrfParams.join(', ')}. An attacker could use these to probe internal services, cloud metadata (169.254.169.254), or private networks.`,
      toolName: tool.name,
      evidence: ssrfParams.join(', '),
    });
  }

  return findings;
}

/**
 * MCP-FS-01 (L1) + MCP-FS-02 (L1): Path Allowlisting & Symlink Resolution
 * Detects tools with file/path parameters lacking pattern restrictions (path traversal risk)
 * and tools whose descriptions reference symbolic links (symlink resolution risk).
 */
function analyzeToolForPathTraversal(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];

  // MCP-FS-01: path-like params without pattern constraint
  const schema = tool.inputSchema;
  if (schema?.properties && typeof schema.properties === 'object') {
    const unsafePaths: string[] = [];
    for (const [name, prop] of Object.entries(schema.properties as Record<string, Record<string, unknown>>)) {
      const lowerName = name.toLowerCase();
      const isPathParam = PATH_PARAM_NAMES.some(p => lowerName === p || lowerName.endsWith(`_${p}`) || lowerName.startsWith(`${p}_`));
      if (isPathParam && prop.type === 'string' && prop.pattern === undefined && prop.enum === undefined) {
        unsafePaths.push(name);
      }
    }

    if (unsafePaths.length > 0) {
      findings.push({
        owaspId: 'MCP05',
        owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
        msssId: 'MCP-FS-01',
        msssLevel: 'L1',
        severity: 'high',
        category: 'Path Traversal',
        title: 'Path parameter without allowlist constraint — path traversal risk',
        description: `The tool "${tool.name}" accepts path/file parameter(s) without a pattern constraint: ${unsafePaths.join(', ')}. An attacker could pass "../../../etc/passwd" or absolute paths to access arbitrary files.`,
        toolName: tool.name,
        evidence: unsafePaths.join(', '),
      });
    }
  }

  // MCP-FS-02: symlink patterns in description
  const desc = tool.description || '';
  for (const pattern of SYMLINK_PATTERNS) {
    const match = desc.match(pattern);
    if (match) {
      findings.push({
        owaspId: 'MCP05',
        owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
        msssId: 'MCP-FS-02',
        msssLevel: 'L1',
        severity: 'medium',
        category: 'Symlink Traversal',
        title: 'Tool description references symlinks — verify canonical path resolution',
        description: `The tool "${tool.name}" mentions symlinks or symbolic links. If symlinks are followed without resolving and validating the canonical path, an attacker can escape the intended file access boundary.`,
        toolName: tool.name,
        evidence: match[0],
      });
      break;
    }
  }

  return findings;
}

/**
 * MCP-EXEC-03 (L2): Argument Separation
 * Detects tools with command/argument parameters that accept raw strings without
 * enum constraints, indicating arguments may be interpolated into shell strings.
 */
function analyzeToolForArgumentInjection(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const schema = tool.inputSchema;
  if (!schema?.properties || typeof schema.properties !== 'object') return findings;

  const dangerousParams: string[] = [];
  for (const [name, prop] of Object.entries(schema.properties as Record<string, Record<string, unknown>>)) {
    const lowerName = name.toLowerCase();
    const isArgParam = ARG_INJECTION_PARAM_NAMES.some(a => lowerName === a || lowerName.endsWith(`_${a}`) || lowerName.startsWith(`${a}_`));
    if (isArgParam && prop.type === 'string' && prop.enum === undefined) {
      dangerousParams.push(name);
    }
  }

  if (dangerousParams.length > 0) {
    findings.push({
      owaspId: 'MCP05',
      owaspTitle: OWASP_MCP_TOP_10.MCP05.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP05.url,
      msssId: 'MCP-EXEC-03',
      msssLevel: 'L2',
      severity: 'high',
      category: 'Argument Injection',
      title: 'Command/argument parameter without enum allowlist — argument injection risk',
      description: `The tool "${tool.name}" accepts unconstrained command or argument parameter(s): ${dangerousParams.join(', ')}. If these are interpolated into a shell command string, an attacker can inject arbitrary commands. Arguments should be passed as arrays with an explicit allowlist (enum).`,
      toolName: tool.name,
      evidence: dangerousParams.join(', '),
    });
  }

  return findings;
}

// ─── Protocol Version Analysis ───────────────────────────────────────────────

/**
 * Flags servers that negotiate a deprecated MCP protocol revision. Older
 * revisions lack the OAuth Resource Server classification, Resource Indicators
 * (RFC 8707) and Protected Resource Metadata (RFC 9728) that mitigate token
 * passthrough and confused-deputy attacks.
 */
function analyzeProtocolVersion(conn: MCPConnection): Finding[] {
  const findings: Finding[] = [];
  const negotiatedVersion = conn.protocolVersion;
  if (!negotiatedVersion) return findings;

  if (!MCP_KNOWN_VERSIONS.includes(negotiatedVersion)) {
    findings.push({
      owaspId: 'MCP04',
      owaspTitle: OWASP_MCP_TOP_10.MCP04.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP04.url,
      severity: 'low',
      category: 'Protocol Version',
      title: `Server negotiated an unrecognized protocol version (${negotiatedVersion})`,
      description: `The server negotiated protocol version "${negotiatedVersion}", which is not a published MCP revision. Custom or pre-release revisions may not implement the security guarantees of the official specification.`,
      evidence: negotiatedVersion,
    });
    return findings;
  }

  const deprecationReason = MCP_DEPRECATED_VERSIONS[negotiatedVersion];
  if (deprecationReason) {
    findings.push({
      owaspId: 'MCP07',
      owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
      severity: 'medium',
      category: 'Protocol Version',
      title: `Server uses a deprecated MCP protocol version (${negotiatedVersion})`,
      description: `${deprecationReason} Upgrade to ${MCP_LATEST_VERSION}, which classifies MCP servers as OAuth Resource Servers, mandates Resource Indicators and Protected Resource Metadata, and adds RFC 9207 issuer validation.`,
      evidence: `Negotiated ${negotiatedVersion}; latest is ${MCP_LATEST_VERSION}`,
    });
  } else if (MCP_LEGACY_VERSIONS.includes(negotiatedVersion)) {
    findings.push({
      owaspId: 'MCP04',
      owaspTitle: OWASP_MCP_TOP_10.MCP04.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP04.url,
      severity: 'low',
      category: 'Protocol Version',
      title: `Server implements a superseded revision (${negotiatedVersion})`,
      description: `The server speaks the handshake era (initialize / Mcp-Session-Id). MCP ${MCP_LATEST_VERSION} replaced it with a stateless model whose security-relevant additions this server does not have: server-side validation of the mirrored Mcp-Method / Mcp-Name headers (so gateways and WAFs cannot be routed one way while the server executes another), RFC 9207 issuer validation on authorization responses, and Client ID Metadata Documents in place of Dynamic Client Registration.`,
      evidence: `Negotiated ${negotiatedVersion}; latest is ${MCP_LATEST_VERSION}`,
    });
  }

  if (conn.era === 'modern' && !conn.probe.discoverImplemented) {
    findings.push({
      owaspId: 'MCP09',
      owaspTitle: OWASP_MCP_TOP_10.MCP09.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP09.url,
      severity: 'low',
      category: 'Protocol Version',
      title: 'Server does not implement server/discover',
      description: `The server accepts stateless requests but does not answer "server/discover", which ${MCP_LATEST_VERSION} makes a MUST. Clients and inventory tooling rely on it to enumerate supported versions, capabilities and server identity; without it a server is harder to discover and govern.`,
      evidence: conn.probe.discoverErrorCode
        ? `server/discover returned JSON-RPC ${conn.probe.discoverErrorCode}`
        : 'server/discover returned no result',
    });
  }

  return findings;
}

// ─── Deprecated features (2026-07-28 feature lifecycle) ──────────────────────

const DEPRECATED_CAPABILITIES: Record<string, string> = {
  roots: 'Pass directories or files via tool parameters, resource URIs, or server configuration instead.',
  sampling: 'Integrate directly with an LLM provider API instead of asking the client to sample.',
  logging: 'Log to stderr (stdio) or use OpenTelemetry instead.',
};

/**
 * Roots, Sampling and Logging entered the Deprecated state in 2026-07-28 with a
 * minimum twelve-month removal window. Sampling in particular hands the server
 * influence over an LLM call the user did not initiate, so continued reliance on
 * it is worth surfacing.
 */
function analyzeDeprecatedFeatures(capabilities: Json): Finding[] {
  const findings: Finding[] = [];
  if (!capabilities || typeof capabilities !== 'object') return findings;

  const declared = Object.keys(DEPRECATED_CAPABILITIES).filter(
    (name) => capabilities[name] !== undefined
  );
  if (declared.length === 0) return findings;

  findings.push({
    owaspId: 'MCP02',
    owaspTitle: OWASP_MCP_TOP_10.MCP02.title,
    owaspUrl: OWASP_MCP_TOP_10.MCP02.url,
    severity: 'low',
    category: 'Deprecated Features',
    title: `Server depends on deprecated MCP features: ${declared.join(', ')}`,
    description: `These capabilities are Deprecated as of ${MCP_LATEST_VERSION} and are eligible for removal after a twelve-month window. ${declared
      .map((d) => `${d}: ${DEPRECATED_CAPABILITIES[d]}`)
      .join(' ')}`,
    evidence: declared.join(', '),
  });

  return findings;
}

// ─── Statelessness / transport hardening (2026-07-28) ────────────────────────

/**
 * 2026-07-28 removed protocol-level sessions. A server that still mints an
 * `Mcp-Session-Id`, or still serves the standalone SSE GET endpoint, is keeping
 * per-connection state that requests can inherit without re-presenting their own
 * authorization context.
 */
async function analyzeStatelessTransport(
  serverUrl: string,
  baseHeaders: Record<string, string>,
  conn: MCPConnection
): Promise<Finding[]> {
  const findings: Finding[] = [];

  if (conn.sessionId) {
    findings.push({
      owaspId: 'MCP10',
      owaspTitle: OWASP_MCP_TOP_10.MCP10.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP10.url,
      severity: conn.era === 'modern' ? 'medium' : 'low',
      category: 'Statelessness',
      title: 'Server mints a protocol-level session (Mcp-Session-Id)',
      description: `The server returned an Mcp-Session-Id header. Protocol-level sessions were removed in ${MCP_LATEST_VERSION}: state carried on the connection rather than in each request means a later request can inherit context — capabilities, identity, resource subscriptions — it never presented credentials for, and it makes session-fixation and cross-tenant bleed possible behind a load balancer.`,
      evidence: `Mcp-Session-Id: ${conn.sessionId}`,
    });
  }

  // The standalone SSE GET endpoint was replaced by subscriptions/listen.
  try {
    const res = await fetch(serverUrl, {
      method: 'GET',
      headers: { ...baseHeaders, Accept: 'text/event-stream' },
      signal: AbortSignal.timeout(5000),
    });
    const contentType = res.headers.get('content-type') || '';
    if (res.ok && contentType.includes('text/event-stream')) {
      findings.push({
        owaspId: 'MCP08',
        owaspTitle: OWASP_MCP_TOP_10.MCP08.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP08.url,
        severity: 'low',
        category: 'Statelessness',
        title: 'Server still serves a standalone SSE stream on GET',
        description: `A GET to the MCP endpoint opened an event stream. ${MCP_LATEST_VERSION} replaced the GET endpoint (and resources/subscribe) with subscriptions/listen, and removed stream resumability; servers on the current revision answer 405 Method Not Allowed. A long-lived server-push channel outside the request/response model is a channel for server-initiated messages that no single request authorized.`,
        evidence: `GET ${new URL(serverUrl).pathname} → ${res.status} ${contentType}`,
      });
    }
    await parseMCPResponse(res).catch(() => undefined);
  } catch {
    /* endpoint not reachable by GET — expected on a current server */
  }

  return findings;
}

// ─── Header mirroring (x-mcp-header, 2026-07-28) ─────────────────────────────

/**
 * `x-mcp-header` mirrors tool arguments into `Mcp-Param-*` HTTP headers so
 * intermediaries can route on them. That makes the annotation a data-egress
 * decision: an annotated value leaves the encrypted body and becomes visible to
 * (and loggable by) every proxy on the path.
 */
function analyzeToolHeaderMirroring(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const bindings = collectXMcpHeaderBindings(tool.inputSchema);
  if (bindings.length === 0) return findings;

  const invalid = bindings.filter((b) => b.violations.length > 0);
  if (invalid.length > 0) {
    findings.push({
      owaspId: 'MCP03',
      owaspTitle: OWASP_MCP_TOP_10.MCP03.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP03.url,
      severity: 'medium',
      category: 'Header Mirroring',
      title: 'Tool declares invalid x-mcp-header annotations',
      description: `The tool "${tool.name}" annotates parameters with x-mcp-header values that violate the ${MCP_LATEST_VERSION} constraints. Conforming clients MUST exclude the whole tool from tools/list; a client that does not will emit malformed headers, and CR/LF or non-token values are a header-injection vector against intermediaries.`,
      toolName: tool.name,
      evidence: invalid
        .map((b) => `${b.path.join('.')} → "${b.header}": ${b.violations.join('; ')}`)
        .join(' | ')
        .slice(0, 300),
    });
  }

  const sensitive = bindings.filter((b) =>
    SENSITIVE_HEADER_NAMES.includes(b.header.toLowerCase())
  );
  if (sensitive.length > 0) {
    findings.push({
      owaspId: 'MCP01',
      owaspTitle: OWASP_MCP_TOP_10.MCP01.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP01.url,
      severity: 'high',
      category: 'Header Mirroring',
      title: 'Tool parameters are mirrored into security-sensitive headers',
      description: `The tool "${tool.name}" asks clients to copy argument values into headers named ${sensitive
        .map((b) => `Mcp-Param-${b.header}`)
        .join(', ')}. Names in this family (Authorization, Cookie, API keys, forwarding headers) let a tool argument impersonate a credential or spoof an origin at any proxy that inspects them, and put the value into request logs along the whole path.`,
      toolName: tool.name,
      evidence: sensitive.map((b) => `${b.path.join('.')} → Mcp-Param-${b.header}`).join(', '),
    });
  }

  const credentialish = bindings.filter(
    (b) =>
      !SENSITIVE_HEADER_NAMES.includes(b.header.toLowerCase()) &&
      /token|secret|password|passwd|credential|session|bearer|signature/i.test(
        `${b.header} ${b.path.join('.')}`
      )
  );
  if (credentialish.length > 0) {
    findings.push({
      owaspId: 'MCP01',
      owaspTitle: OWASP_MCP_TOP_10.MCP01.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP01.url,
      severity: 'medium',
      category: 'Header Mirroring',
      title: 'Credential-shaped parameter mirrored into an HTTP header',
      description: `The tool "${tool.name}" mirrors a parameter whose name suggests a secret into an Mcp-Param-* header. Mirrored values are readable by every intermediary on the path and routinely land in access logs; mirror only routing keys such as region or tenant.`,
      toolName: tool.name,
      evidence: credentialish.map((b) => `${b.path.join('.')} → Mcp-Param-${b.header}`).join(', '),
    });
  }

  return findings;
}

// ─── Remote $ref in tool schemas (2026-07-28 JSON Schema rules) ──────────────

function collectRemoteRefs(schema: Json, refs: string[] = [], depth = 0): string[] {
  if (!schema || typeof schema !== 'object' || depth > 12) return refs;

  if (typeof schema.$ref === 'string' && /^https?:\/\//i.test(schema.$ref)) {
    refs.push(schema.$ref);
  }
  for (const value of Object.values(schema)) {
    if (Array.isArray(value)) {
      for (const item of value) collectRemoteRefs(item, refs, depth + 1);
    } else if (value && typeof value === 'object') {
      collectRemoteRefs(value, refs, depth + 1);
    }
  }
  return refs;
}

/**
 * JSON Schema 2020-12 lets `$ref` point at a network URI. 2026-07-28 forbids
 * implementations from dereferencing those automatically — a server that ships
 * them is asking clients to fetch third-party schema content, which is both an
 * SSRF trigger and a supply-chain hook into argument validation.
 */
function analyzeSchemaRemoteRefs(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const refs = [
    ...collectRemoteRefs(tool.inputSchema),
    ...collectRemoteRefs(tool.outputSchema),
  ];
  if (refs.length === 0) return findings;

  findings.push({
    owaspId: 'MCP04',
    owaspTitle: OWASP_MCP_TOP_10.MCP04.title,
    owaspUrl: OWASP_MCP_TOP_10.MCP04.url,
    msssId: 'MCP-NET-01',
    msssLevel: 'L1',
    severity: 'medium',
    category: 'Schema Supply Chain',
    title: 'Tool schema contains network $ref targets',
    description: `The schema for "${tool.name}" references remote URIs. Implementations MUST NOT dereference network $refs automatically (${MCP_LATEST_VERSION}); a client that does gives the schema host control over argument validation and can be pointed at internal addresses. Inline the definitions or use local $defs.`,
    toolName: tool.name,
    evidence: [...new Set(refs)].slice(0, 3).join(', '),
  });

  return findings;
}

// ─── Cache hints (2026-07-28 CacheableResult) ────────────────────────────────

/**
 * `cacheScope: "public"` tells shared gateways they may serve a stored response
 * to any caller. On a server that requires authorization, that is a cross-tenant
 * disclosure primitive; per-user results must be `"private"`.
 */
function analyzeCacheHints(
  operation: string,
  result: Json,
  requiresAuth: boolean,
  era: MCPConnection['era']
): Finding[] {
  const findings: Finding[] = [];
  if (!result || typeof result !== 'object') return findings;

  const hints = cacheHintsOf(result);

  if (hints.cacheScope === 'public' && requiresAuth) {
    findings.push({
      owaspId: 'MCP10',
      owaspTitle: OWASP_MCP_TOP_10.MCP10.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP10.url,
      severity: operation === 'resources/read' ? 'high' : 'medium',
      category: 'Caching',
      title: `${operation} is marked cacheScope: "public" on an authenticated server`,
      description: `The server answered an authorized ${operation} with cacheScope "public", which permits any shared gateway or caching proxy to store the response and serve it to a different caller. Results that vary per authorization context MUST be "private" so caches are never shared across contexts.`,
      evidence: `${operation} → cacheScope: public${hints.hasTtl ? `, ttlMs: ${hints.ttlMs}` : ''}`,
    });
  }

  if (era === 'modern' && !hints.valid && resultTypeOf(result) !== 'input_required') {
    findings.push({
      owaspId: 'MCP08',
      owaspTitle: OWASP_MCP_TOP_10.MCP08.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP08.url,
      severity: 'info',
      category: 'Caching',
      title: `${operation} omits required cache hints`,
      description: `${MCP_LATEST_VERSION} requires ttlMs (>= 0) and cacheScope ("public" or "private") on complete results from ${operation}. Without an explicit scope, intermediaries have no instruction about whether the response may be shared between callers.`,
      evidence: `ttlMs: ${hints.hasTtl ? hints.ttlMs : 'absent'}, cacheScope: ${
        hints.hasScope ? hints.cacheScope : 'absent'
      }`,
    });
  }

  return findings;
}

// ─── OAuth 2.1 / Authorization Metadata (RFC 9728 / RFC 8707) ────────────────

/**
 * Probes for OAuth 2.1 Protected Resource Metadata (RFC 9728) and inspects the
 * WWW-Authenticate challenge. The 2025-06-18 spec requires unauthenticated
 * requests to a protected server to return 401 with a resource_metadata pointer
 * so clients can discover the authorization server and request audience-bound
 * tokens (Resource Indicators, RFC 8707).
 */
async function analyzeAuthorizationMetadata(
  serverUrl: string,
  authType: string | undefined,
  connected: boolean,
  wwwAuthenticate: string | null
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Only meaningful for remote (non-localhost) HTTPS/HTTP servers
  const isLocal = serverUrl.includes('localhost') || serverUrl.includes('127.0.0.1');

  let prmFound = false;
  let prmAuthorizationServers: string[] = [];
  try {
    const origin = new URL(serverUrl).origin;
    const prmRes = await fetch(`${origin}/.well-known/oauth-protected-resource`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (prmRes.ok) {
      const prm = await prmRes.json().catch(() => null);
      if (prm && (prm.authorization_servers || prm.resource)) {
        prmFound = true;
        if (Array.isArray(prm.authorization_servers)) {
          prmAuthorizationServers = prm.authorization_servers.filter(
            (s: unknown): s is string => typeof s === 'string'
          );
        }
      }
    }
  } catch {
    /* metadata endpoint not reachable */
  }

  // If the server answered an unauthenticated request successfully AND exposes
  // no authorization metadata, it is effectively open.
  if ((!authType || authType === 'none') && connected && !prmFound && !isLocal) {
    findings.push({
      owaspId: 'MCP07',
      owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
      msssId: 'MCP-AUTHZ-01',
      msssLevel: 'L3',
      severity: 'high',
      category: 'Authorization',
      title: 'No OAuth 2.1 authorization — server is openly accessible',
      description: 'The server answered an unauthenticated request and exposes no Protected Resource Metadata (RFC 9728) at /.well-known/oauth-protected-resource. Since MCP 2025-06-18, remote servers should act as OAuth 2.1 Resource Servers and advertise their authorization server so clients can obtain audience-bound tokens.',
      evidence: 'No /.well-known/oauth-protected-resource and unauthenticated request succeeded',
    });
  }

  // Server challenges for auth but does not point to its resource metadata.
  if (wwwAuthenticate && !/resource_metadata/i.test(wwwAuthenticate) && !prmFound) {
    findings.push({
      owaspId: 'MCP07',
      owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
      severity: 'low',
      category: 'Authorization',
      title: 'WWW-Authenticate challenge omits resource_metadata pointer',
      description: 'The server returns a 401 challenge but the WWW-Authenticate header does not include a resource_metadata parameter. RFC 9728 / MCP 2025-06-18 expect this so clients can discover the authorization server and request audience-restricted tokens.',
      evidence: wwwAuthenticate.substring(0, 120),
    });
  }

  findings.push(...(await analyzeAuthorizationServer(serverUrl, prmAuthorizationServers)));

  return findings;
}

// ─── Authorization server metadata (RFC 9207 / CIMD, 2026-07-28) ─────────────

/**
 * Fetches the authorization server's metadata and checks the two registration
 * and issuer-validation requirements 2026-07-28 added:
 *
 *  - `authorization_response_iss_parameter_supported` (RFC 9207). Without the
 *    `iss` parameter a client cannot tell which authorization server produced a
 *    code, which is what makes mix-up attacks work.
 *  - `client_id_metadata_document_supported` (CIMD). Dynamic Client
 *    Registration is deprecated in favour of CIMD; a DCR-only server accepts
 *    unauthenticated registrations from anyone who can reach the endpoint.
 */
async function analyzeAuthorizationServer(
  serverUrl: string,
  authorizationServers: string[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  const candidates = authorizationServers.length
    ? authorizationServers
    : [new URL(serverUrl).origin];

  for (const issuer of candidates.slice(0, 2)) {
    const metadata = await fetchAuthorizationServerMetadata(issuer);
    if (!metadata) continue;

    if (metadata.authorization_response_iss_parameter_supported !== true) {
      findings.push({
        owaspId: 'MCP07',
        owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
        severity: 'medium',
        category: 'Authorization',
        title: 'Authorization server does not advertise RFC 9207 issuer identification',
        description: `The metadata for ${issuer} does not set authorization_response_iss_parameter_supported. MCP ${MCP_LATEST_VERSION} expects authorization servers to return the iss parameter in authorization responses and requires clients to validate it against the recorded issuer before redeeming a code. Without it, a client talking to several authorization servers cannot detect a code issued by a different one — the mix-up attack.`,
        evidence: `${issuer} — authorization_response_iss_parameter_supported: ${
          metadata.authorization_response_iss_parameter_supported ?? 'absent'
        }`,
      });
    }

    const cimd = metadata.client_id_metadata_document_supported === true;
    const dcr = typeof metadata.registration_endpoint === 'string';

    if (!cimd && dcr) {
      findings.push({
        owaspId: 'MCP07',
        owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
        severity: 'low',
        category: 'Authorization',
        title: 'Authorization server offers only Dynamic Client Registration',
        description: `${issuer} exposes a registration_endpoint but does not advertise client_id_metadata_document_supported. OAuth 2.0 Dynamic Client Registration (RFC 7591) is deprecated as an MCP registration mechanism as of ${MCP_LATEST_VERSION} in favour of Client ID Metadata Documents, where the client identifier is an HTTPS URL the authorization server fetches and validates. An open DCR endpoint mints client records for any caller that can reach it.`,
        evidence: `${issuer} — registration_endpoint present, client_id_metadata_document_supported absent`,
      });
    }

    if (!cimd && !dcr) {
      findings.push({
        owaspId: 'MCP07',
        owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
        severity: 'info',
        category: 'Authorization',
        title: 'Authorization server supports no automatic client registration',
        description: `${issuer} advertises neither Client ID Metadata Documents nor a registration endpoint, so clients with no prior relationship must be registered out of band. That is a valid choice; it is listed here because ${MCP_LATEST_VERSION} expects CIMD to be the default path for clients and servers that have never met.`,
        evidence: issuer,
      });
    }
  }

  return findings;
}

async function fetchAuthorizationServerMetadata(issuer: string): Promise<Json> {
  let origin: string;
  let pathPart: string;
  try {
    const url = new URL(issuer);
    origin = url.origin;
    pathPart = url.pathname.replace(/\/$/, '');
  } catch {
    return null;
  }

  // RFC 8414 inserts the well-known segment between host and issuer path;
  // OpenID Discovery appends it. Try both, plus the bare origin.
  const candidates = [
    `${origin}/.well-known/oauth-authorization-server${pathPart}`,
    `${origin}${pathPart}/.well-known/openid-configuration`,
    `${origin}/.well-known/openid-configuration`,
  ];

  for (const url of [...new Set(candidates)]) {
    try {
      const res = await fetch(url, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) continue;
      const json = await res.json().catch(() => null);
      if (json && (json.issuer || json.authorization_endpoint || json.token_endpoint)) {
        return json;
      }
    } catch {
      /* try the next candidate */
    }
  }

  return null;
}

// ─── Tool Annotations (2025-06-18+) ──────────────────────────────────────────

const MUTATING_TOOL_HINTS = [
  /\bdelete\b/i, /\bremove\b/i, /\bdrop\b/i, /\bwrite\b/i, /\bupdate\b/i,
  /\bcreate\b/i, /\bmodify\b/i, /\bsend\b/i, /\bexecute\b/i, /\bpurchase\b/i,
  /\btransfer\b/i, /\brevoke\b/i, /\boverwrite\b/i, /\bdeploy\b/i, /\bpush\b/i,
];

/**
 * Tools that appear to mutate state should declare ToolAnnotations
 * (readOnlyHint / destructiveHint / idempotentHint / openWorldHint) so hosts can
 * make informed trust and confirmation decisions. Note: annotations are hints
 * and MUST NOT be relied upon for security enforcement.
 */
function analyzeToolAnnotations(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const name = tool.name || '';
  const desc = tool.description || '';
  const looksMutating = MUTATING_TOOL_HINTS.some(p => p.test(name) || p.test(desc));

  if (looksMutating && !tool.annotations) {
    findings.push({
      owaspId: 'MCP02',
      owaspTitle: OWASP_MCP_TOP_10.MCP02.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP02.url,
      severity: 'low',
      category: 'Tool Annotations',
      title: 'State-changing tool declares no annotations',
      description: `The tool "${tool.name}" appears to modify state but declares no ToolAnnotations. Without readOnlyHint/destructiveHint/idempotentHint, a host cannot prompt for confirmation on destructive actions. (Annotations are advisory hints, not a security control.)`,
      toolName: tool.name,
      evidence: name,
    });
  }

  // A tool marked readOnly whose name/description strongly implies mutation is suspicious.
  if (tool.annotations?.readOnlyHint === true && looksMutating) {
    findings.push({
      owaspId: 'MCP03',
      owaspTitle: OWASP_MCP_TOP_10.MCP03.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP03.url,
      severity: 'medium',
      category: 'Tool Annotations',
      title: 'Tool claims readOnlyHint but appears to modify state',
      description: `The tool "${tool.name}" is annotated readOnlyHint: true yet its name/description implies state changes. Misleading annotations can trick a host into skipping user confirmation. Annotations must never be trusted as a security boundary.`,
      toolName: tool.name,
      evidence: `readOnlyHint: true on "${tool.name}"`,
    });
  }

  return findings;
}

// ─── MCP Apps / Interactive UI Extension (SEP-1865) ──────────────────────────
// UI resources use the ui:// scheme and are linked from tools via _meta. Host
// security obligations: sandboxed iframes, CSP from resource metadata, audited
// postMessage JSON-RPC, and explicit consent for UI-initiated tool calls.

const UI_META_KEYS = [
  'openai/outputTemplate', 'openai/output_template',
  'mcp/ui', 'mcpui', 'ui', 'mcp-apps', 'apps/ui',
];

function getUiTemplateRef(meta: Record<string, unknown> | undefined): string | null {
  if (!meta || typeof meta !== 'object') return null;
  for (const key of Object.keys(meta)) {
    const lower = key.toLowerCase();
    if (UI_META_KEYS.some(k => lower === k.toLowerCase()) || lower.includes('outputtemplate') || lower.includes('ui')) {
      const val = meta[key];
      if (typeof val === 'string') return val;
      if (val && typeof val === 'object') return JSON.stringify(val);
    }
  }
  return null;
}

function isUiResource(resource: MCPResource): boolean {
  const uri = (resource.uri || '').toLowerCase();
  const mime = (resource.mimeType || '').toLowerCase();
  return uri.startsWith('ui://') || mime === 'text/html' || mime === 'text/uri-list' || mime.includes('html');
}

/**
 * Detects MCP Apps / interactive UI surfaces and flags the host-side security
 * obligations that apply when rendering server-provided HTML.
 */
function analyzeUIExtension(tools: MCPTool[], resources: MCPResource[]): Finding[] {
  const findings: Finding[] = [];

  const uiResources = resources.filter(isUiResource);
  const uiTools = tools.filter(t => getUiTemplateRef(t._meta) !== null);

  if (uiResources.length === 0 && uiTools.length === 0) return findings;

  findings.push({
    owaspId: 'MCP03',
    owaspTitle: OWASP_MCP_TOP_10.MCP03.title,
    owaspUrl: OWASP_MCP_TOP_10.MCP03.url,
    severity: 'info',
    category: 'MCP Apps / UI',
    title: 'Server ships interactive UI (MCP Apps extension)',
    description: `Detected ${uiResources.length} UI resource(s) and ${uiTools.length} UI-linked tool(s). Per the MCP Apps extension (SEP-1865), the host MUST render this content in a sandboxed iframe with restricted permissions, enforce a Content-Security-Policy derived from the resource metadata, treat all postMessage traffic as auditable JSON-RPC, and require explicit user consent for any UI-initiated tool call.`,
    evidence: [...uiResources.map(r => r.uri), ...uiTools.map(t => t.name)].filter(Boolean).slice(0, 5).join(', '),
  });

  // External-origin UI content is higher risk: it can load attacker-controlled scripts.
  for (const r of uiResources) {
    const html = `${r.description || ''} ${JSON.stringify(r._meta || {})}`;
    const externalSrc = html.match(/https?:\/\/[^\s"'<>]+/i);
    if (externalSrc && !/modelcontextprotocol|localhost|127\.0\.0\.1/i.test(externalSrc[0])) {
      findings.push({
        owaspId: 'MCP03',
        owaspTitle: OWASP_MCP_TOP_10.MCP03.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP03.url,
        severity: 'medium',
        category: 'MCP Apps / UI',
        title: 'UI resource references external origin',
        description: `The UI resource "${r.uri || r.name}" references an external URL. Loading third-party scripts or frames into a UI template widens the attack surface for cross-site scripting and data exfiltration from the rendered view. Pin UI assets to the server origin and enforce a strict CSP.`,
        evidence: externalSrc[0].substring(0, 120),
      });
    }

    // UI HTML carrying hidden instructions is a poisoning vector for the agent.
    for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
      if (pattern.test(html)) {
        findings.push({
          owaspId: 'MCP06',
          owaspTitle: OWASP_MCP_TOP_10.MCP06.title,
          owaspUrl: OWASP_MCP_TOP_10.MCP06.url,
          severity: 'high',
          category: 'MCP Apps / UI',
          title: 'Hidden instructions in UI resource',
          description: `The UI resource "${r.uri || r.name}" contains hidden-instruction patterns. Rendered UI text can be read back into model context and used to subvert the agent's intent.`,
          evidence: pattern.source,
        });
        break;
      }
    }
  }

  return findings;
}

// ─── Resources & Prompts Analysis ────────────────────────────────────────────

const SENSITIVE_RESOURCE_URI_PATTERNS = [
  /file:\/\/.*\/(etc|root|home|users|var|proc|sys)\b/i,
  /\.env\b/i, /id_rsa/i, /\.ssh/i, /credentials/i, /\.aws/i, /\.kube/i,
  /passwd/i, /shadow/i, /\.pem\b/i, /\.key\b/i,
];

function analyzeResources(resources: MCPResource[]): Finding[] {
  const findings: Finding[] = [];

  for (const r of resources) {
    const uri = r.uri || '';

    // Local filesystem resources exposed over a remote server are a disclosure risk.
    if (/^file:\/\//i.test(uri)) {
      findings.push({
        owaspId: 'MCP10',
        owaspTitle: OWASP_MCP_TOP_10.MCP10.title,
        owaspUrl: OWASP_MCP_TOP_10.MCP10.url,
        severity: 'low',
        category: 'Resource Exposure',
        title: 'Resource exposes a local filesystem path',
        description: `The resource "${r.name || uri}" uses a file:// URI. Exposing host filesystem resources over MCP can leak local files into model context.`,
        evidence: uri.substring(0, 120),
      });
    }

    for (const pattern of SENSITIVE_RESOURCE_URI_PATTERNS) {
      if (pattern.test(uri) || pattern.test(r.name || '') || pattern.test(r.description || '')) {
        findings.push({
          owaspId: 'MCP01',
          owaspTitle: OWASP_MCP_TOP_10.MCP01.title,
          owaspUrl: OWASP_MCP_TOP_10.MCP01.url,
          severity: 'high',
          category: 'Resource Exposure',
          title: 'Resource references a sensitive location',
          description: `The resource "${r.name || uri}" references a sensitive path or credential store. Such resources can expose secrets if read into context.`,
          evidence: (uri || r.name || '').substring(0, 120),
        });
        break;
      }
    }

    // Prompt-injection patterns embedded in resource descriptions.
    for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
      if (pattern.test(r.description || '')) {
        findings.push({
          owaspId: 'MCP06',
          owaspTitle: OWASP_MCP_TOP_10.MCP06.title,
          owaspUrl: OWASP_MCP_TOP_10.MCP06.url,
          severity: 'high',
          category: 'Resource Poisoning',
          title: 'Hidden instructions in resource description',
          description: `The resource "${r.name || uri}" description contains hidden-instruction patterns that could manipulate the agent when the resource is surfaced.`,
          evidence: pattern.source,
        });
        break;
      }
    }
  }

  return findings;
}

function analyzePrompts(prompts: MCPPrompt[]): Finding[] {
  const findings: Finding[] = [];

  for (const p of prompts) {
    const text = `${p.description || ''} ${JSON.stringify(p.arguments || [])}`;
    for (const pattern of HIDDEN_INSTRUCTION_PATTERNS.concat(SHADOWING_PATTERNS)) {
      if (pattern.test(text)) {
        findings.push({
          owaspId: 'MCP06',
          owaspTitle: OWASP_MCP_TOP_10.MCP06.title,
          owaspUrl: OWASP_MCP_TOP_10.MCP06.url,
          severity: 'high',
          category: 'Prompt Poisoning',
          title: 'Hidden / intent-subverting instructions in prompt template',
          description: `The prompt "${p.name || 'unnamed'}" contains patterns that could hijack the agent's intent when the prompt is expanded into context.`,
          toolName: p.name,
          evidence: pattern.source,
        });
        break;
      }
    }
  }

  return findings;
}

// ─── Lethal Trifecta (untrusted input + private data + exfiltration) ─────────
// A single server that can ingest untrusted content, access private data, AND
// communicate externally enables prompt-injection-driven data exfiltration.

function analyzeLethalTrifecta(tools: MCPTool[]): Finding[] {
  const findings: Finding[] = [];

  const blob = tools.map(t => `${t.name} ${t.description || ''}`).join(' ').toLowerCase();

  const ingestsUntrusted = /\b(fetch|browse|crawl|read[_ ]?url|scrape|http|web|email|inbox|message|webhook|rss|document)\b/.test(blob);
  const accessesPrivate = /\b(database|secret|credential|token|private|internal|file|filesystem|env|config|customer|account|record)\b/.test(blob);
  const canExfiltrate = /\b(send|post|upload|publish|email|webhook|notify|http|request|export|share|message)\b/.test(blob);

  if (ingestsUntrusted && accessesPrivate && canExfiltrate) {
    findings.push({
      owaspId: 'MCP10',
      owaspTitle: OWASP_MCP_TOP_10.MCP10.title,
      owaspUrl: OWASP_MCP_TOP_10.MCP10.url,
      severity: 'medium',
      category: 'Lethal Trifecta',
      title: 'Server combines untrusted input, private data access, and external communication',
      description: 'This server exposes tools that can (1) ingest untrusted external content, (2) access private/internal data, and (3) communicate externally. Together these form the "lethal trifecta": a prompt-injection payload in untrusted content can coerce the agent into exfiltrating private data. Separate these capabilities across trust boundaries or require human approval for outbound actions.',
      evidence: 'untrusted-ingest + private-data + external-send capabilities co-located',
    });
  }

  return findings;
}

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader, customHeaders } = await request.json();

    if (!serverUrl) {
      return NextResponse.json({ error: 'Server URL required' }, { status: 400 });
    }

    const reqHeaders = buildBaseHeaders({ authType, authValue, authHeader, customHeaders });

    let tools: MCPTool[] = [];
    let resources: MCPResource[] = [];
    let prompts: MCPPrompt[] = [];

    // Step 1: Connect — probe the stateless revision first, fall back to the
    // initialize handshake, and remember which era the server speaks.
    const conn = await connectMCP(serverUrl, reqHeaders);

    if (conn.era === 'unknown') {
      return NextResponse.json({
        error: `Failed to connect: ${conn.error || 'Unknown error'}`,
        findings: [{
          owaspId: 'MCP07',
          owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
          owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
          severity: 'high',
          category: 'Connection',
          title: 'Cannot connect to MCP server',
          description: 'The scanner was unable to establish a connection to the MCP server. It answered neither "server/discover" (MCP 2026-07-28) nor "initialize" (handshake era). The server may be down, unreachable, or rejecting connections.',
          evidence: serverUrl,
        }],
        summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
      });
    }

    // Normalized handshake view: a stateless server reports its identity in the
    // result's `_meta`, a handshake server in `initialize.serverInfo`.
    const handshakeResult: Json = {
      ...(conn.discover || conn.initialize || {}),
      serverInfo: conn.serverInfo,
      instructions: conn.instructions,
    };
    const responseHeaders: Headers | null = conn.headers;
    const wwwAuthenticate: string | null = conn.wwwAuthenticate;
    const rawInit: Json = conn.raw;
    let rawTools: Json = null;

    const negotiatedVersion: string | undefined = conn.protocolVersion;
    const requiresAuth = !!(authType && authType !== 'none');

    // Step 2: Enumerate tools, resources and prompts in the server's own era.
    const toolsCall = await mcpCall(conn, serverUrl, reqHeaders, 'tools/list');
    rawTools = toolsCall.raw;
    tools = toolsCall.result?.tools || [];

    const resourcesCall = await mcpCall(conn, serverUrl, reqHeaders, 'resources/list');
    resources = resourcesCall.result?.resources || [];

    const promptsCall = await mcpCall(conn, serverUrl, reqHeaders, 'prompts/list');
    prompts = promptsCall.result?.prompts || [];

    // Step 3: Run analysis
    const findings: Finding[] = [];

    // Protocol version / spec revision checks
    findings.push(...analyzeProtocolVersion(conn));

    // Deprecated features (Roots / Sampling / Logging)
    findings.push(...analyzeDeprecatedFeatures(conn.capabilities));

    // Statelessness and transport hardening (2026-07-28)
    findings.push(...await analyzeStatelessTransport(serverUrl, reqHeaders, conn));

    // Cache hints on cacheable results (2026-07-28)
    findings.push(...analyzeCacheHints('tools/list', toolsCall.result, requiresAuth, conn.era));
    findings.push(...analyzeCacheHints('resources/list', resourcesCall.result, requiresAuth, conn.era));
    findings.push(...analyzeCacheHints('prompts/list', promptsCall.result, requiresAuth, conn.era));

    // Server-level checks
    findings.push(...analyzeServerCapabilities(
      conn.capabilities,
      tools,
      serverUrl
    ));

    // Authentication posture — reaching this point means the server answered.
    findings.push(...analyzeAuthenticationPosture(authType, true));

    // OAuth 2.1 authorization metadata (RFC 9728 / RFC 8707 / RFC 9207 / CIMD)
    findings.push(...await analyzeAuthorizationMetadata(serverUrl, authType, true, wwwAuthenticate));

    // Instructions field analysis
    findings.push(...analyzeInstructionsField(handshakeResult));

    // Information leakage (version, framework fingerprinting)
    findings.push(...analyzeInformationLeakage(handshakeResult, tools));

    // HTTP response header analysis
    if (responseHeaders) {
      findings.push(...analyzeResponseHeaders(responseHeaders, serverUrl));
    }

    // Per-tool checks
    for (const tool of tools) {
      // Existing OWASP-based checks
      findings.push(...analyzeToolForHiddenInstructions(tool));
      findings.push(...analyzeToolForSensitiveFileAccess(tool));
      findings.push(...analyzeToolForShadowing(tool));
      findings.push(...analyzeToolForExfiltration(tool));
      findings.push(...analyzeToolForCommandInjection(tool));
      findings.push(...analyzeToolForSecretLeakage(tool));
      // MSSS-aligned checks
      findings.push(...analyzeToolInputSchemaValidation(tool));  // MCP-INPUT-01
      findings.push(...analyzeToolInputBounds(tool));            // MCP-INPUT-02
      findings.push(...analyzeToolForSSRF(tool));                // MCP-NET-01
      findings.push(...analyzeToolForPathTraversal(tool));       // MCP-FS-01 + MCP-FS-02
      findings.push(...analyzeToolForArgumentInjection(tool));   // MCP-EXEC-03
      // 2025-06-18+ spec checks
      findings.push(...analyzeToolAnnotations(tool));
      // 2026-07-28 spec checks
      findings.push(...analyzeToolHeaderMirroring(tool));
      findings.push(...analyzeSchemaRemoteRefs(tool));
    }

    // Resources, prompts and interactive-UI (MCP Apps) checks
    findings.push(...analyzeResources(resources));
    findings.push(...analyzePrompts(prompts));
    findings.push(...analyzeUIExtension(tools, resources));

    // Cross-tool checks
    findings.push(...analyzeCrossToolViolations(tools));

    // Aggregate / multi-tool risk
    findings.push(...analyzeLethalTrifecta(tools));

    // Generate summary
    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length,
    };

    // OWASP coverage: which categories were checked
    const owaspCoverage = Object.values(OWASP_MCP_TOP_10).map(item => ({
      id: item.id,
      title: item.title,
      url: item.url,
      findingsCount: findings.filter(f => f.owaspId === item.id).length,
      checked: true,
    }));

    // MSSS coverage: which controls produced findings (remotely detectable subset)
    const msssControls = Object.values(MSSS_CONTROLS).map(ctrl => ({
      id: ctrl.id,
      level: ctrl.level,
      title: ctrl.title,
      findingsCount: findings.filter(f => f.msssId === ctrl.id).length,
      checked: true,
    }));

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      serverUrl,
      serverInfo: conn.serverInfo,
      protocolVersion: negotiatedVersion || null,
      protocolEra: conn.era,
      supportedVersions: conn.supportedVersions || null,
      latestProtocolVersion: MCP_LATEST_VERSION,
      specUrl: MCP_SPEC_URLS.spec,
      toolsCount: tools.length,
      resourcesCount: resources.length,
      promptsCount: prompts.length,
      findings,
      summary,
      owaspCoverage,
      msssControls,
      raw: { init: rawInit, tools: rawTools },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Security scan failed' },
      { status: 500 }
    );
  }
}
