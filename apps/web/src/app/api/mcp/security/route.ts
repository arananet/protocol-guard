import { NextRequest, NextResponse } from 'next/server';

/**
 * MCP Security Scanner — OWASP MCP Top 10 vulnerability analysis
 * 
 * Implements checks inspired by:
 *  - OWASP MCP Top 10 (https://owasp.org/www-project-mcp-top-10/)
 *  - mcp-shield patterns (https://github.com/riseandignite/mcp-shield)
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

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  owaspId: string;
  owaspTitle: string;
  owaspUrl: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  toolName?: string;
  evidence?: string;
}

interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string }>;
    required?: string[];
  };
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

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const { serverUrl, authType, authValue, authHeader } = await request.json();

    if (!serverUrl) {
      return NextResponse.json({ error: 'Server URL required' }, { status: 400 });
    }

    const reqHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
    };

    if (authType && authType !== 'none' && authValue) {
      if (authType === 'api_key') {
        reqHeaders[authHeader || 'Authorization'] = authValue;
      } else if (authType === 'bearer') {
        reqHeaders[authHeader || 'Authorization'] = `Bearer ${authValue}`;
      } else if (authType === 'basic') {
        reqHeaders[authHeader || 'Authorization'] = `Basic ${Buffer.from(authValue).toString('base64')}`;
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let initResult: any = null;
    let tools: MCPTool[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let rawInit: any = null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let rawTools: any = null;
    let responseHeaders: Headers | null = null;

    // Step 1: Initialize
    try {
      const initResponse = await fetch(serverUrl, {
        method: 'POST',
        headers: reqHeaders,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2024-11-05',
            capabilities: {},
            clientInfo: { name: 'protocol-guard-scanner', version: '1.0.0' },
          },
        }),
      });

      responseHeaders = initResponse.headers;
      rawInit = await parseResponse(initResponse);
      initResult = rawInit?.result || rawInit;
    } catch (err) {
      return NextResponse.json({
        error: `Failed to connect: ${err instanceof Error ? err.message : 'Unknown error'}`,
        findings: [{
          owaspId: 'MCP07',
          owaspTitle: OWASP_MCP_TOP_10.MCP07.title,
          owaspUrl: OWASP_MCP_TOP_10.MCP07.url,
          severity: 'high',
          category: 'Connection',
          title: 'Cannot connect to MCP server',
          description: 'The scanner was unable to establish a connection to the MCP server. The server may be down, unreachable, or rejecting connections.',
          evidence: serverUrl,
        }],
        summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
      });
    }

    // Send initialized notification
    try {
      await fetch(serverUrl, {
        method: 'POST',
        headers: reqHeaders,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }),
      });
    } catch { /* ignore */ }

    // Step 2: List tools
    try {
      const toolsResponse = await fetch(serverUrl, {
        method: 'POST',
        headers: reqHeaders,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/list',
          params: {},
        }),
      });

      rawTools = await parseResponse(toolsResponse);
      const toolsResult = rawTools?.result || rawTools;
      tools = toolsResult?.tools || [];
    } catch {
      // tools/list not supported
    }

    // Step 3: Run analysis
    const findings: Finding[] = [];

    // Server-level checks
    findings.push(...analyzeServerCapabilities(
      initResult?.capabilities,
      tools,
      serverUrl
    ));

    // Authentication posture
    findings.push(...analyzeAuthenticationPosture(authType, !!initResult));

    // Instructions field analysis
    findings.push(...analyzeInstructionsField(initResult));

    // Information leakage (version, framework fingerprinting)
    findings.push(...analyzeInformationLeakage(initResult, tools));

    // HTTP response header analysis
    if (responseHeaders) {
      findings.push(...analyzeResponseHeaders(responseHeaders, serverUrl));
    }

    // Per-tool checks
    for (const tool of tools) {
      findings.push(...analyzeToolForHiddenInstructions(tool));
      findings.push(...analyzeToolForSensitiveFileAccess(tool));
      findings.push(...analyzeToolForShadowing(tool));
      findings.push(...analyzeToolForExfiltration(tool));
      findings.push(...analyzeToolForCommandInjection(tool));
      findings.push(...analyzeToolForSecretLeakage(tool));
    }

    // Cross-tool checks
    findings.push(...analyzeCrossToolViolations(tools));

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

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      serverUrl,
      serverInfo: initResult?.serverInfo || null,
      toolsCount: tools.length,
      findings,
      summary,
      owaspCoverage,
      raw: { init: rawInit, tools: rawTools },
    });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Security scan failed' },
      { status: 500 }
    );
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function parseResponse(response: Response): Promise<any> {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('text/event-stream')) {
    const text = await response.text();
    const dataLine = text.split('\n').find(l => l.startsWith('data:'));
    if (dataLine) return JSON.parse(dataLine.replace(/^data:\s*/, ''));
    return { _rawSSE: text };
  }
  return response.json();
}
