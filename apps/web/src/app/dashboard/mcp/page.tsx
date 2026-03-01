'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Navbar } from '@/components/Navbar';
import {
  ChevronDown, ChevronUp, ExternalLink, Server, CheckCircle, XCircle,
  AlertTriangle, Info, Shield, Play, Wrench, Loader2, EyeOff,
} from 'lucide-react';

type AuthType = 'none' | 'api_key' | 'bearer' | 'basic';
type Tab = 'compliance' | 'interactive' | 'security';

// ─── Compliance Types ────────────────────────────────────────────────────────

interface ComplianceResult {
  passed: boolean;
  ruleId: string;
  message: string;
  severity: 'critical' | 'warning' | 'info';
  docUrl?: string;
}

interface ComplianceReport {
  timestamp: string;
  protocolVersion: string;
  specUrl: string;
  serverName: string;
  results: ComplianceResult[];
  passedCount: number;
  failedCount: number;
  warningCount: number;
  serverResponse?: Record<string, unknown>;
}

// ─── Interactive Types ───────────────────────────────────────────────────────

interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string }>;
    required?: string[];
  };
}

interface ToolsResult {
  serverInfo: unknown;
  tools: MCPTool[];
  raw: unknown;
}

interface CallToolResult {
  toolName: string;
  result: unknown;
  isError: boolean;
  raw: unknown;
}

// ─── Security Types ──────────────────────────────────────────────────────────

interface SecurityFinding {
  owaspId: string;
  owaspTitle: string;
  owaspUrl: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  toolName?: string;
  evidence?: string;
}

interface OWASPCoverage {
  id: string;
  title: string;
  url: string;
  findingsCount: number;
  checked: boolean;
}

interface SecurityReport {
  timestamp: string;
  serverUrl: string;
  serverInfo: unknown;
  toolsCount: number;
  findings: SecurityFinding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
  owaspCoverage: OWASPCoverage[];
  raw: unknown;
}

export default function MCPPage() {
  const [activeTab, setActiveTab] = useState<Tab>('compliance');
  const [serverUrl, setServerUrl] = useState('');
  const [authType, setAuthType] = useState<AuthType>('none');
  const [authValue, setAuthValue] = useState('');
  const [authHeader, setAuthHeader] = useState('Authorization');

  // Compliance state
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [error, setError] = useState('');
  const [showRawResponse, setShowRawResponse] = useState(false);

  // Interactive state
  const [toolsLoading, setToolsLoading] = useState(false);
  const [toolsResult, setToolsResult] = useState<ToolsResult | null>(null);
  const [toolsError, setToolsError] = useState('');
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null);
  const [toolArgs, setToolArgs] = useState<Record<string, string>>({});
  const [callLoading, setCallLoading] = useState(false);
  const [callResult, setCallResult] = useState<CallToolResult | null>(null);
  const [callError, setCallError] = useState('');
  const [showToolsRaw, setShowToolsRaw] = useState(false);
  const [showCallRaw, setShowCallRaw] = useState(false);

  // Security state
  const [scanLoading, setScanLoading] = useState(false);
  const [scanReport, setScanReport] = useState<SecurityReport | null>(null);
  const [scanError, setScanError] = useState('');
  const [showScanRaw, setShowScanRaw] = useState(false);

  // ─── Compliance Test ─────────────────────────────────────────────────────

  const runTest = async () => {
    if (!serverUrl) return;
    setLoading(true);
    setError('');
    setReport(null);

    try {
      const response = await fetch('/api/mcp/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serverUrl, authType, authValue, authHeader }),
      });

      if (!response.ok) throw new Error('Failed to connect to MCP server');
      setReport(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed');
    } finally {
      setLoading(false);
    }
  };

  // ─── Interactive: List Tools ─────────────────────────────────────────────

  const listTools = async () => {
    if (!serverUrl) return;
    setToolsLoading(true);
    setToolsError('');
    setToolsResult(null);
    setSelectedTool(null);
    setCallResult(null);

    try {
      const response = await fetch('/api/mcp/tools', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serverUrl, authType, authValue, authHeader }),
      });

      if (!response.ok) throw new Error('Failed to list tools');
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      setToolsResult(data);
    } catch (err) {
      setToolsError(err instanceof Error ? err.message : 'Failed to list tools');
    } finally {
      setToolsLoading(false);
    }
  };

  // ─── Interactive: Call Tool ──────────────────────────────────────────────

  const callTool = async () => {
    if (!serverUrl || !selectedTool) return;
    setCallLoading(true);
    setCallError('');
    setCallResult(null);

    try {
      // Parse arg values
      const args: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(toolArgs)) {
        if (val === '') continue;
        try { args[key] = JSON.parse(val); } catch { args[key] = val; }
      }

      const response = await fetch('/api/mcp/call-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serverUrl, authType, authValue, authHeader, toolName: selectedTool.name, arguments: args }),
      });

      if (!response.ok) throw new Error('Failed to call tool');
      const data = await response.json();
      if (data.error) throw new Error(data.error);
      setCallResult(data);
    } catch (err) {
      setCallError(err instanceof Error ? err.message : 'Tool call failed');
    } finally {
      setCallLoading(false);
    }
  };

  // ─── Security Scan ───────────────────────────────────────────────────────

  const runSecurityScan = async () => {
    if (!serverUrl) return;
    setScanLoading(true);
    setScanError('');
    setScanReport(null);

    try {
      const response = await fetch('/api/mcp/security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serverUrl, authType, authValue, authHeader }),
      });

      const data = await response.json();
      if (data.error && !data.findings) throw new Error(data.error);
      setScanReport(data);
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Security scan failed');
    } finally {
      setScanLoading(false);
    }
  };

  // ─── Helpers ─────────────────────────────────────────────────────────────

  const getSeverityIcon = (severity: string, passed: boolean) => {
    if (passed) return <CheckCircle className="w-4 h-4 text-green-700 dark:text-green-400" />;
    switch (severity) {
      case 'critical': return <XCircle className="w-4 h-4 text-red-600 dark:text-red-400" />;
      case 'warning': return <AlertTriangle className="w-4 h-4 text-yellow-600 dark:text-yellow-400" />;
      default: return <Info className="w-4 h-4 text-blue-600 dark:text-blue-400" />;
    }
  };

  const getSeverityBadge = (severity: string, passed: boolean) => {
    if (passed) return <span className="px-2 py-0.5 text-xs rounded-full bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">Passed</span>;
    switch (severity) {
      case 'critical': return <span className="px-2 py-0.5 text-xs rounded-full bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">Critical</span>;
      case 'warning': return <span className="px-2 py-0.5 text-xs rounded-full bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400">Warning</span>;
      default: return <span className="px-2 py-0.5 text-xs rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">Info</span>;
    }
  };

  const getSecurityBadge = (severity: string) => {
    switch (severity) {
      case 'critical': return <span className="px-2 py-0.5 text-xs rounded-full bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 font-semibold">Critical</span>;
      case 'high': return <span className="px-2 py-0.5 text-xs rounded-full bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400 font-semibold">High</span>;
      case 'medium': return <span className="px-2 py-0.5 text-xs rounded-full bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400">Medium</span>;
      case 'low': return <span className="px-2 py-0.5 text-xs rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">Low</span>;
      default: return <span className="px-2 py-0.5 text-xs rounded-full bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400">Info</span>;
    }
  };

  const getDocLinkLabel = (url: string) => {
    if (url.includes('authentication')) return 'Authentication Spec';
    if (url.includes('capabilities')) return 'Capabilities Spec';
    if (url.includes('basic-concepts')) return 'Basic Concepts Spec';
    return 'Protocol Reference';
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />

      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-3xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-2">
              <Server className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-bold">MCP Server Testing</h2>
            </div>
            <p className="text-muted-foreground">
              Validate your <a href="https://modelcontextprotocol.io" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Model Context Protocol</a> server against the official specification.
              MCP enables AI models to securely interact with tools, resources, and data sources through a standardised protocol.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
              <span>
                Spec version: <span className="font-mono font-bold">2024-11-05</span>
              </span>
              <span className="hidden sm:inline">·</span>
              <a href="https://modelcontextprotocol.io/docs/basic-concepts/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline flex items-center gap-1">
                Full Specification <ExternalLink className="w-3 h-3" />
              </a>
              <a href="https://github.com/modelcontextprotocol" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline flex items-center gap-1">
                GitHub <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>

          {/* How it works */}
          <div className="mb-6 p-4 border rounded-lg bg-muted/30 text-sm text-muted-foreground space-y-1">
            <p className="font-medium text-foreground">How it works</p>
            <p>1. Enter the URL of your MCP server (e.g. <code className="bg-muted px-1 rounded">https://your-mcp-server.com</code>).</p>
            <p>2. We send a JSON-RPC <code className="bg-muted px-1 rounded">initialize</code> handshake to negotiate capabilities.</p>
            <p>3. The server response is validated against 7 compliance rules covering protocol version, server info, capabilities, tools, resources, authentication, and the initialize method.</p>
            <p className="mt-2 pt-2 border-t border-border/50">You can also run Protocol Guard <strong className="text-foreground">locally via Docker</strong> or integrate the <strong className="text-foreground">CLI scanner into your CI/CD pipeline</strong> to gate deployments on compliance.</p>
          </div>

          {/* No-storage notice */}
          <div className="flex items-center gap-3 p-3 rounded-lg border border-primary/20 bg-primary/5 mb-6">
            <EyeOff className="w-4 h-4 text-primary flex-shrink-0" />
            <p className="text-xs text-muted-foreground">
              <span className="font-medium text-foreground">No data stored.</span> URLs, credentials, and scan results are never saved. Everything runs in real-time and exists only in your browser session.
            </p>
          </div>

          {/* Shared Server URL + Auth */}
          <div className="space-y-4 mb-6">
            <div>
              <label className="block text-sm font-medium mb-2">Server URL</label>
              <input
                type="text"
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
                placeholder="https://your-mcp-server.com"
                className="w-full px-4 py-2.5 border rounded-lg bg-background focus:ring-2 focus:ring-primary focus:border-primary"
              />
            </div>

            <div className="p-5 border rounded-lg bg-muted/30">
              <h3 className="font-medium mb-4">Authentication (optional)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex flex-col">
                  <label className="block text-sm font-medium mb-2">Auth Type</label>
                  <select
                    value={authType}
                    onChange={(e) => setAuthType(e.target.value as AuthType)}
                    className="w-full h-11 px-4 py-2.5 border rounded-lg bg-background focus:ring-2 focus:ring-primary focus:border-primary"
                  >
                    <option value="none">None</option>
                    <option value="api_key">API Key</option>
                    <option value="bearer">Bearer Token</option>
                    <option value="basic">Basic Auth</option>
                  </select>
                </div>
                <div className="flex flex-col">
                  <label className="block text-sm font-medium mb-2">Header Name</label>
                  <input
                    type="text"
                    value={authHeader}
                    onChange={(e) => setAuthHeader(e.target.value)}
                    placeholder="Authorization"
                    className="w-full h-11 px-4 py-2.5 border rounded-lg bg-background focus:ring-2 focus:ring-primary focus:border-primary"
                  />
                </div>
              </div>
              {authType !== 'none' && (
                <div className="mt-4">
                  <label className="block text-sm font-medium mb-2">
                    {authType === 'basic' ? 'Username:Password' : 'Token / Key'}
                  </label>
                  <input
                    type="password"
                    value={authValue}
                    onChange={(e) => setAuthValue(e.target.value)}
                    placeholder={authType === 'basic' ? 'user:pass' : 'your-token-here'}
                    className="w-full px-4 py-2.5 border rounded-lg bg-background focus:ring-2 focus:ring-primary focus:border-primary"
                  />
                </div>
              )}
            </div>
          </div>

          {/* Tabs */}
          <div className="flex border-b mb-6">
            {[
              { id: 'compliance' as Tab, label: 'Compliance', icon: CheckCircle },
              { id: 'interactive' as Tab, label: 'Interactive', icon: Play },
              { id: 'security' as Tab, label: 'Security Scan', icon: Shield },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>

          {/* ━━━ TAB: Compliance ━━━ */}
          {activeTab === 'compliance' && (
            <div>
              <div className="mb-4 text-sm text-muted-foreground">
                Testing against MCP <span className="font-mono font-bold">2024-11-05</span>
              </div>

              <button
                onClick={runTest}
                disabled={loading || !serverUrl}
                className="w-full py-3 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                {loading ? 'Testing...' : 'Run Compliance Test'}
              </button>

              {error && (
                <div className="mt-6 p-4 border border-red-500 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600">{error}</div>
              )}

              {report && (
                <div className="mt-8 space-y-6">
                  <div className="flex items-center justify-between text-sm">
                    <div className="text-muted-foreground">
                      Protocol: <span className="font-mono font-bold">{report.protocolVersion}</span>
                    </div>
                    <a href={report.specUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-primary hover:underline">
                      View Spec <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>

                  <div className="flex items-center justify-between">
                    <h3 className="text-xl font-semibold">Compliance Report</h3>
                    <div className="text-sm text-muted-foreground">{report.serverName}</div>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="p-4 border rounded-lg text-center bg-green-50 dark:bg-green-900/20">
                      <div className="text-2xl font-bold text-green-700 dark:text-green-400">{report.passedCount}</div>
                      <div className="text-sm text-muted-foreground">Passed</div>
                    </div>
                    <div className="p-4 border rounded-lg text-center bg-red-50 dark:bg-red-900/20">
                      <div className="text-2xl font-bold text-red-700 dark:text-red-400">{report.failedCount}</div>
                      <div className="text-sm text-muted-foreground">Failed</div>
                    </div>
                    <div className="p-4 border rounded-lg text-center bg-yellow-50 dark:bg-yellow-900/20">
                      <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{report.warningCount}</div>
                      <div className="text-sm text-muted-foreground">Warnings</div>
                    </div>
                  </div>

                  {report.serverResponse && (
                    <div className="border rounded-lg overflow-hidden">
                      <button onClick={() => setShowRawResponse(!showRawResponse)} className="w-full flex items-center justify-between p-4 bg-muted hover:bg-muted/80 transition-colors">
                        <span className="font-medium flex items-center gap-2"><Server className="w-4 h-4" />Server Raw Response</span>
                        {showRawResponse ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                      {showRawResponse && (
                        <div className="p-4 bg-background overflow-x-auto">
                          <pre className="text-xs font-mono whitespace-pre-wrap">{JSON.stringify(report.serverResponse, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="space-y-3">
                    {report.results.map((result, idx) => (
                      <div
                        key={idx}
                        className={`p-4 border rounded-lg ${
                          result.passed
                            ? 'border-green-600/20 bg-green-50/50 dark:bg-green-900/10'
                            : result.severity === 'critical'
                              ? 'border-red-500/30 bg-red-50/30 dark:bg-red-900/10'
                              : result.severity === 'warning'
                                ? 'border-yellow-500/30 bg-yellow-50/30 dark:bg-yellow-900/10'
                                : 'border-blue-500/20 bg-blue-50/30 dark:bg-blue-900/10'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {getSeverityIcon(result.severity, result.passed)}
                            <span className="font-medium font-mono text-sm">{result.ruleId}</span>
                          </div>
                          {getSeverityBadge(result.severity, result.passed)}
                        </div>
                        <p className="text-sm text-muted-foreground mt-2 ml-7">{result.message}</p>
                        {result.docUrl && (
                          <div className="mt-3 ml-7 flex items-center gap-2 px-3 py-2 rounded-md bg-muted/50 border border-border/50 w-fit">
                            <ExternalLink className="w-3.5 h-3.5 text-primary flex-shrink-0" />
                            <a href={result.docUrl} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline font-medium">
                              {getDocLinkLabel(result.docUrl)}
                            </a>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ━━━ TAB: Interactive ━━━ */}
          {activeTab === 'interactive' && (
            <div className="space-y-6">
              <button
                onClick={listTools}
                disabled={toolsLoading || !serverUrl}
                className="w-full py-3 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
              >
                {toolsLoading ? <><Loader2 className="w-4 h-4 animate-spin" />Discovering Tools...</> : <><Wrench className="w-4 h-4" />List Available Tools</>}
              </button>

              {toolsError && (
                <div className="p-4 border border-red-500 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600">{toolsError}</div>
              )}

              {toolsResult && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold">Available Tools ({toolsResult.tools.length})</h3>
                    <button onClick={() => setShowToolsRaw(!showToolsRaw)} className="text-xs text-muted-foreground hover:text-foreground">
                      {showToolsRaw ? 'Hide' : 'Show'} Raw
                    </button>
                  </div>

                  {showToolsRaw && (
                    <div className="border rounded-lg p-4 bg-muted/30 overflow-x-auto">
                      <pre className="text-xs font-mono whitespace-pre-wrap">{JSON.stringify(toolsResult.raw, null, 2)}</pre>
                    </div>
                  )}

                  {toolsResult.tools.length === 0 ? (
                    <div className="p-6 border rounded-lg text-center text-muted-foreground">
                      This server does not expose any tools.
                    </div>
                  ) : (
                    <div className="grid gap-3">
                      {toolsResult.tools.map((tool) => (
                        <button
                          key={tool.name}
                          onClick={() => {
                            setSelectedTool(tool);
                            setToolArgs({});
                            setCallResult(null);
                            setCallError('');
                          }}
                          className={`p-4 border rounded-lg text-left transition-all hover:border-primary ${
                            selectedTool?.name === tool.name ? 'border-primary bg-primary/5' : ''
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            <Wrench className="w-4 h-4 text-primary flex-shrink-0" />
                            <span className="font-mono font-semibold text-sm">{tool.name}</span>
                          </div>
                          {tool.description && (
                            <p className="text-sm text-muted-foreground mt-1 ml-6">{tool.description}</p>
                          )}
                          {tool.inputSchema?.properties && (
                            <div className="mt-2 ml-6 flex flex-wrap gap-1">
                              {Object.entries(tool.inputSchema.properties).map(([name, schema]) => (
                                <span key={name} className="text-xs px-1.5 py-0.5 bg-muted rounded font-mono">
                                  {name}{tool.inputSchema?.required?.includes(name) ? '*' : ''}: {schema.type || 'any'}
                                </span>
                              ))}
                            </div>
                          )}
                        </button>
                      ))}
                    </div>
                  )}

                  {/* Tool Execution Panel */}
                  {selectedTool && (
                    <div className="border-2 border-primary/30 rounded-lg p-5 space-y-4 bg-primary/5">
                      <div className="flex items-center gap-2">
                        <Play className="w-5 h-5 text-primary" />
                        <h4 className="font-semibold">Call: <span className="font-mono">{selectedTool.name}</span></h4>
                      </div>

                      {selectedTool.inputSchema?.properties && Object.keys(selectedTool.inputSchema.properties).length > 0 ? (
                        <div className="space-y-3">
                          <p className="text-sm text-muted-foreground">Enter arguments:</p>
                          {Object.entries(selectedTool.inputSchema.properties).map(([name, schema]) => (
                            <div key={name}>
                              <label className="block text-sm font-medium mb-1">
                                <span className="font-mono">{name}</span>
                                {selectedTool.inputSchema?.required?.includes(name) && <span className="text-red-500 ml-1">*</span>}
                                <span className="text-muted-foreground font-normal ml-2">({schema.type || 'any'})</span>
                              </label>
                              {schema.description && (
                                <p className="text-xs text-muted-foreground mb-1">{schema.description}</p>
                              )}
                              <input
                                type="text"
                                value={toolArgs[name] || ''}
                                onChange={(e) => setToolArgs({ ...toolArgs, [name]: e.target.value })}
                                placeholder={`Enter ${name}...`}
                                className="w-full px-3 py-2 border rounded-lg bg-background focus:ring-2 focus:ring-primary focus:border-primary text-sm"
                              />
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">This tool takes no arguments.</p>
                      )}

                      <button
                        onClick={callTool}
                        disabled={callLoading}
                        className="w-full py-2.5 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
                      >
                        {callLoading ? <><Loader2 className="w-4 h-4 animate-spin" />Executing...</> : <><Play className="w-4 h-4" />Execute Tool</>}
                      </button>

                      {callError && (
                        <div className="p-3 border border-red-500 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 text-sm">{callError}</div>
                      )}

                      {callResult && (
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <h5 className="font-medium text-sm">Result</h5>
                            <div className="flex items-center gap-2">
                              {callResult.isError && <span className="text-xs text-red-600 font-medium">Error</span>}
                              <button onClick={() => setShowCallRaw(!showCallRaw)} className="text-xs text-muted-foreground hover:text-foreground">
                                {showCallRaw ? 'Hide' : 'Show'} Raw
                              </button>
                            </div>
                          </div>
                          <div className="border rounded-lg p-4 bg-background overflow-x-auto">
                            <pre className="text-xs font-mono whitespace-pre-wrap">
                              {JSON.stringify(showCallRaw ? callResult.raw : callResult.result, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ━━━ TAB: Security Scan ━━━ */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              <div className="p-4 border rounded-lg bg-muted/30">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-5 h-5 text-primary" />
                  <h3 className="font-semibold">OWASP MCP Top 10 Security Scan</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Scans your MCP server for vulnerabilities based on the{' '}
                  <a href="https://owasp.org/www-project-mcp-top-10/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                    OWASP MCP Top 10
                  </a>.
                  Analyzes tool descriptions, server capabilities, and configurations for hidden instructions, data exfiltration, tool poisoning, and more.
                  Detection patterns inspired by{' '}
                  <a href="https://github.com/riseandignite/mcp-shield" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                    mcp-shield
                  </a>.
                </p>
              </div>

              <button
                onClick={runSecurityScan}
                disabled={scanLoading || !serverUrl}
                className="w-full py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
              >
                {scanLoading ? <><Loader2 className="w-4 h-4 animate-spin" />Scanning...</> : <><Shield className="w-4 h-4" />Run Security Scan</>}
              </button>

              {scanError && (
                <div className="p-4 border border-red-500 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600">{scanError}</div>
              )}

              {scanReport && (
                <div className="space-y-6">
                  {/* Summary Bar */}
                  <div className="grid grid-cols-5 gap-3">
                    {[
                      { label: 'Critical', count: scanReport.summary.critical, color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' },
                      { label: 'High', count: scanReport.summary.high, color: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400' },
                      { label: 'Medium', count: scanReport.summary.medium, color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400' },
                      { label: 'Low', count: scanReport.summary.low, color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400' },
                      { label: 'Info', count: scanReport.summary.info, color: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400' },
                    ].map(({ label, count, color }) => (
                      <div key={label} className={`p-3 rounded-lg text-center ${color}`}>
                        <div className="text-xl font-bold">{count}</div>
                        <div className="text-xs">{label}</div>
                      </div>
                    ))}
                  </div>

                  {/* Overall Score */}
                  <div className={`p-4 border rounded-lg text-center ${
                    scanReport.summary.critical > 0 ? 'border-red-500 bg-red-50 dark:bg-red-900/20' :
                    scanReport.summary.high > 0 ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20' :
                    scanReport.summary.medium > 0 ? 'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20' :
                    'border-green-500 bg-green-50 dark:bg-green-900/20'
                  }`}>
                    <span className="text-lg font-bold">
                      {scanReport.summary.critical > 0 ? 'Critical Issues Found' :
                       scanReport.summary.high > 0 ? 'High Risk Issues Found' :
                       scanReport.summary.medium > 0 ? 'Moderate Issues Found' :
                       scanReport.summary.total > 0 ? 'Low Risk Issues' :
                       'No Issues Found — Clean!'}
                    </span>
                    <p className="text-sm text-muted-foreground mt-1">
                      {scanReport.toolsCount} tools scanned • {scanReport.summary.total} total findings
                    </p>
                  </div>

                  {/* OWASP Coverage */}
                  <div className="border rounded-lg overflow-hidden">
                    <div className="p-4 bg-muted">
                      <h4 className="font-medium">OWASP MCP Top 10 Coverage</h4>
                    </div>
                    <div className="divide-y">
                      {scanReport.owaspCoverage.map((item) => (
                        <div key={item.id} className="flex items-center justify-between p-3 hover:bg-muted/30">
                          <div className="flex items-center gap-3">
                            <span className="font-mono text-xs font-bold text-primary w-14">{item.id}</span>
                            <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-sm hover:text-primary hover:underline">
                              {item.title}
                            </a>
                          </div>
                          <span className={`text-xs font-mono ${item.findingsCount > 0 ? 'text-red-600 dark:text-red-400 font-bold' : 'text-green-600 dark:text-green-400'}`}>
                            {item.findingsCount > 0 ? `${item.findingsCount} finding${item.findingsCount > 1 ? 's' : ''}` : 'Clean'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Findings */}
                  {scanReport.findings.length > 0 && (
                    <div className="space-y-3">
                      <h4 className="font-semibold">Findings</h4>
                      {scanReport.findings.map((finding, idx) => (
                        <div
                          key={idx}
                          className={`p-4 border rounded-lg ${
                            finding.severity === 'critical' ? 'border-red-500/30 bg-red-50/30 dark:bg-red-900/10' :
                            finding.severity === 'high' ? 'border-orange-500/30 bg-orange-50/30 dark:bg-orange-900/10' :
                            finding.severity === 'medium' ? 'border-yellow-500/30 bg-yellow-50/30 dark:bg-yellow-900/10' :
                            finding.severity === 'low' ? 'border-blue-500/20 bg-blue-50/30 dark:bg-blue-900/10' :
                            'border-border bg-muted/30'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-bold text-primary">{finding.owaspId}</span>
                              <span className="text-xs text-muted-foreground">|</span>
                              <span className="text-xs text-muted-foreground">{finding.category}</span>
                            </div>
                            {getSecurityBadge(finding.severity)}
                          </div>
                          <h5 className="font-medium text-sm">{finding.title}</h5>
                          <p className="text-sm text-muted-foreground mt-1">{finding.description}</p>
                          {finding.evidence && (
                            <div className="mt-2 px-3 py-1.5 bg-muted rounded text-xs font-mono">
                              Evidence: {finding.evidence}
                            </div>
                          )}
                          {finding.toolName && (
                            <div className="mt-1 text-xs text-muted-foreground">
                              Tool: <span className="font-mono">{finding.toolName}</span>
                            </div>
                          )}
                          <a href={finding.owaspUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 mt-2 text-xs text-primary hover:underline">
                            OWASP Reference <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Raw Response */}
                  <div className="border rounded-lg overflow-hidden">
                    <button onClick={() => setShowScanRaw(!showScanRaw)} className="w-full flex items-center justify-between p-4 bg-muted hover:bg-muted/80 transition-colors">
                      <span className="font-medium flex items-center gap-2"><Server className="w-4 h-4" />Raw Scan Data</span>
                      {showScanRaw ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                    {showScanRaw && (
                      <div className="p-4 bg-background overflow-x-auto">
                        <pre className="text-xs font-mono whitespace-pre-wrap">{JSON.stringify(scanReport.raw, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </main>

      <footer className="border-t py-6">
        <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground">
            © 2026 Protocol Guard. Built by Eduardo Arana & Soda 🥤
          </p>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <a href="https://github.com/arananet/protocol-guard" target="_blank" rel="noopener noreferrer" className="hover:text-foreground">Open Source on GitHub</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
