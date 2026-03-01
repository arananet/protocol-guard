'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Navbar } from '@/components/Navbar';
import {
  ChevronDown, ChevronUp, ExternalLink, Globe, CheckCircle, XCircle,
  AlertTriangle, Info, Shield, Play, Zap, MessageSquare, Loader2, EyeOff,
} from 'lucide-react';

type AuthType = 'none' | 'bearer' | 'basic' | 'api_key';
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
  agentName: string;
  results: ComplianceResult[];
  passedCount: number;
  failedCount: number;
  warningCount: number;
  agentCard?: Record<string, unknown>;
  resolvedUrl?: string;
}

// ─── Interactive Types ───────────────────────────────────────────────────────

interface A2ASkill {
  id?: string;
  name?: string;
  description?: string;
  tags?: string[];
  examples?: string[];
}

interface A2AAgentCard {
  name?: string;
  description?: string;
  url?: string;
  version?: string;
  skills?: A2ASkill[];
  capabilities?: {
    streaming?: boolean;
    pushNotifications?: boolean;
    stateTransitionHistory?: boolean;
  };
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  provider?: { organization?: string; url?: string };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

interface TaskResult {
  taskId: string;
  status: unknown;
  artifacts: unknown;
  history: unknown;
  raw: unknown;
}

// ─── Security Types ──────────────────────────────────────────────────────────

interface SecurityFinding {
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
}

interface SecurityCategory {
  name: string;
  count: number;
}

interface SecurityReport {
  timestamp: string;
  agentUrl: string;
  resolvedUrl: string;
  agentName: string;
  agentVersion: string | null;
  skillsCount: number;
  findings: SecurityFinding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
  categories: SecurityCategory[];
  raw: { agentCard: A2AAgentCard };
}

export default function A2APage() {
  const [activeTab, setActiveTab] = useState<Tab>('compliance');
  const [agentCardUrl, setAgentCardUrl] = useState('');
  const [authType, setAuthType] = useState<AuthType>('none');
  const [authValue, setAuthValue] = useState('');
  const [authHeader, setAuthHeader] = useState('Authorization');

  // Compliance state
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [error, setError] = useState('');
  const [showRawResponse, setShowRawResponse] = useState(false);

  // Interactive state
  const [agentCard, setAgentCard] = useState<A2AAgentCard | null>(null);
  const [cardLoading, setCardLoading] = useState(false);
  const [cardError, setCardError] = useState('');
  const [showCardRaw, setShowCardRaw] = useState(false);
  const [taskMessage, setTaskMessage] = useState('');
  const [taskLoading, setTaskLoading] = useState(false);
  const [taskResult, setTaskResult] = useState<TaskResult | null>(null);
  const [taskError, setTaskError] = useState('');
  const [showTaskRaw, setShowTaskRaw] = useState(false);

  // Security state
  const [scanLoading, setScanLoading] = useState(false);
  const [scanReport, setScanReport] = useState<SecurityReport | null>(null);
  const [scanError, setScanError] = useState('');
  const [showScanRaw, setShowScanRaw] = useState(false);

  // ─── Compliance Test ─────────────────────────────────────────────────────

  const runTest = async () => {
    if (!agentCardUrl) return;
    setLoading(true);
    setError('');
    setReport(null);

    try {
      const response = await fetch('/api/a2a/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentCardUrl, authType, authValue, authHeader }),
      });

      if (!response.ok) throw new Error('Failed to fetch or validate agent card');
      setReport(await response.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Validation failed');
    } finally {
      setLoading(false);
    }
  };

  // ─── Interactive: Fetch Agent Card ───────────────────────────────────────

  const fetchAgentCard = async () => {
    if (!agentCardUrl) return;
    setCardLoading(true);
    setCardError('');
    setAgentCard(null);
    setTaskResult(null);

    try {
      // Use server-side proxy to avoid CORS issues
      const res = await fetch('/api/a2a/agent-card', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentUrl: agentCardUrl, authType, authValue, authHeader }),
      });

      const data = await res.json();

      if (!res.ok || data.error) {
        throw new Error(data.error || 'Failed to fetch agent card');
      }

      if (data.card) {
        setAgentCard(data.card);
        return;
      }

      throw new Error('Could not fetch agent card from any well-known location');
    } catch (err) {
      setCardError(err instanceof Error ? err.message : 'Failed to fetch agent card');
    } finally {
      setCardLoading(false);
    }
  };

  // ─── Interactive: Send Task ──────────────────────────────────────────────

  const sendTask = async () => {
    if (!agentCardUrl || !taskMessage) return;
    setTaskLoading(true);
    setTaskError('');
    setTaskResult(null);

    try {
      const response = await fetch('/api/a2a/send-task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentUrl: agentCard?.url || agentCardUrl,
          authType,
          authValue,
          authHeader,
          message: taskMessage,
        }),
      });

      const data = await response.json();
      if (data.error) throw new Error(data.error);
      setTaskResult(data);
    } catch (err) {
      setTaskError(err instanceof Error ? err.message : 'Task sending failed');
    } finally {
      setTaskLoading(false);
    }
  };

  // ─── Security Scan ───────────────────────────────────────────────────────

  const runSecurityScan = async () => {
    if (!agentCardUrl) return;
    setScanLoading(true);
    setScanError('');
    setScanReport(null);

    try {
      const response = await fetch('/api/a2a/security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentUrl: agentCardUrl }),
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
    if (url.includes('skills')) return 'Skills Spec';
    if (url.includes('latest')) return 'Agent Card Spec';
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
              <Globe className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-bold">A2A Agent Testing</h2>
            </div>
            <p className="text-muted-foreground">
              Validate your <a href="https://a2a-protocol.org" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Agent-to-Agent Protocol</a> implementation against the official specification.
              A2A enables AI agents to discover, communicate, and collaborate with each other through a standardised protocol.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
              <span>
                Spec version: <span className="font-mono font-bold">2025-01-17</span>
              </span>
              <span className="hidden sm:inline">·</span>
              <a href="https://a2a-protocol.org/latest/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline flex items-center gap-1">
                Full Specification <ExternalLink className="w-3 h-3" />
              </a>
              <a href="https://github.com/a2a-protocol" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline flex items-center gap-1">
                GitHub <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>

          {/* How it works */}
          <div className="mb-6 p-4 border rounded-lg bg-muted/30 text-sm text-muted-foreground space-y-1">
            <p className="font-medium text-foreground">How it works</p>
            <p>1. Enter the URL of the agent card (e.g. <code className="bg-muted px-1 rounded">https://your-agent.com/agent.json</code>).</p>
            <p>2. We fetch the agent card from the URL or <code className="bg-muted px-1 rounded">/.well-known/agent.json</code> discovery endpoint.</p>
            <p>3. The returned JSON Agent Card is validated against 9 compliance rules covering agent name, description, URL, version, capabilities, skills, input/output modes, and authentication.</p>
            <p className="mt-2 pt-2 border-t border-border/50">You can also run Protocol Guard <strong className="text-foreground">locally via Docker</strong> or integrate the <strong className="text-foreground">CLI scanner into your CI/CD pipeline</strong> to gate deployments on compliance.</p>
          </div>

          {/* No-storage notice */}
          <div className="flex items-center gap-3 p-3 rounded-lg border border-primary/20 bg-primary/5 mb-6">
            <EyeOff className="w-4 h-4 text-primary flex-shrink-0" />
            <p className="text-xs text-muted-foreground">
              <span className="font-medium text-foreground">No data stored.</span> URLs, credentials, and scan results are never saved. Everything runs in real-time and exists only in your browser session.
            </p>
          </div>

          {/* Shared Agent URL + Auth */}
          <div className="space-y-4 mb-6">
            <div>
              <label className="block text-sm font-medium mb-2">Agent Card URL</label>
              <input
                type="text"
                value={agentCardUrl}
                onChange={(e) => setAgentCardUrl(e.target.value)}
                placeholder="https://your-agent.com/agent.json"
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
                    <option value="bearer">Bearer Token</option>
                    <option value="basic">Basic Auth</option>
                    <option value="api_key">API Key</option>
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
                Testing against A2A <span className="font-mono font-bold">2025-01-17</span>
              </div>

              <button
                onClick={runTest}
                disabled={loading || !agentCardUrl}
                className="w-full py-3 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                {loading ? 'Validating...' : 'Run Compliance Test'}
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

                  {report.resolvedUrl && report.resolvedUrl !== agentCardUrl && (
                    <div className="text-xs text-muted-foreground bg-muted/50 rounded-md px-3 py-2">
                      Agent card resolved from: <span className="font-mono">{report.resolvedUrl}</span>
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <h3 className="text-xl font-semibold">Compliance Report</h3>
                    <div className="text-sm text-muted-foreground">{report.agentName}</div>
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

                  {report.agentCard && (
                    <div className="border rounded-lg overflow-hidden">
                      <button onClick={() => setShowRawResponse(!showRawResponse)} className="w-full flex items-center justify-between p-4 bg-muted hover:bg-muted/80 transition-colors">
                        <span className="font-medium flex items-center gap-2"><Globe className="w-4 h-4" />Agent Card Raw Content</span>
                        {showRawResponse ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                      {showRawResponse && (
                        <div className="p-4 bg-background overflow-x-auto">
                          <pre className="text-xs font-mono whitespace-pre-wrap">{JSON.stringify(report.agentCard, null, 2)}</pre>
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
                onClick={fetchAgentCard}
                disabled={cardLoading || !agentCardUrl}
                className="w-full py-3 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
              >
                {cardLoading ? <><Loader2 className="w-4 h-4 animate-spin" />Fetching Agent Card...</> : <><Zap className="w-4 h-4" />Fetch Agent Card & Skills</>}
              </button>

              {cardError && (
                <div className="p-4 border border-red-500 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600">{cardError}</div>
              )}

              {agentCard && (
                <div className="space-y-6">
                  {/* Agent Info */}
                  <div className="border rounded-lg p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold">{agentCard.name || 'Unknown Agent'}</h3>
                      <button onClick={() => setShowCardRaw(!showCardRaw)} className="text-xs text-muted-foreground hover:text-foreground">
                        {showCardRaw ? 'Hide' : 'Show'} Raw
                      </button>
                    </div>
                    {agentCard.description && (
                      <p className="text-sm text-muted-foreground">{agentCard.description}</p>
                    )}
                    <div className="flex flex-wrap gap-2 text-xs">
                      {agentCard.version && (
                        <span className="px-2 py-1 bg-muted rounded font-mono">v{agentCard.version}</span>
                      )}
                      {agentCard.url && (
                        <span className="px-2 py-1 bg-muted rounded font-mono">{agentCard.url}</span>
                      )}
                      {agentCard.provider?.organization && (
                        <span className="px-2 py-1 bg-primary/10 text-primary rounded">{agentCard.provider.organization}</span>
                      )}
                    </div>

                    {/* Capabilities */}
                    {agentCard.capabilities && (
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(agentCard.capabilities).map(([key, val]) => (
                          <span key={key} className={`px-2 py-1 text-xs rounded ${val ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-muted text-muted-foreground'}`}>
                            {key}: {val ? 'Yes' : 'No'}
                          </span>
                        ))}
                      </div>
                    )}

                    {showCardRaw && (
                      <div className="border rounded-lg p-4 bg-muted/30 overflow-x-auto">
                        <pre className="text-xs font-mono whitespace-pre-wrap">{JSON.stringify(agentCard, null, 2)}</pre>
                      </div>
                    )}
                  </div>

                  {/* Skills */}
                  {agentCard.skills && agentCard.skills.length > 0 ? (
                    <div className="space-y-3">
                      <h4 className="font-semibold flex items-center gap-2">
                        <Zap className="w-4 h-4 text-primary" />
                        Skills ({agentCard.skills.length})
                      </h4>
                      <div className="grid gap-3">
                        {agentCard.skills.map((skill, idx) => (
                          <div key={idx} className="p-4 border rounded-lg hover:border-primary/30 transition-colors">
                            <div className="font-medium text-sm">{skill.name || skill.id || `Skill ${idx + 1}`}</div>
                            {skill.description && (
                              <p className="text-sm text-muted-foreground mt-1">{skill.description}</p>
                            )}
                            {skill.tags && skill.tags.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-2">
                                {skill.tags.map((tag, tidx) => (
                                  <span key={tidx} className="px-1.5 py-0.5 text-xs bg-primary/10 text-primary rounded">{tag}</span>
                                ))}
                              </div>
                            )}
                            {skill.examples && skill.examples.length > 0 && (
                              <div className="mt-2 space-y-1">
                                <span className="text-xs text-muted-foreground">Examples:</span>
                                {skill.examples.map((ex, eidx) => (
                                  <div key={eidx} className="text-xs font-mono bg-muted px-2 py-1 rounded">{ex}</div>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="p-6 border rounded-lg text-center text-muted-foreground">
                      This agent does not declare any skills.
                    </div>
                  )}

                  {/* Send Task */}
                  <div className="border-2 border-primary/30 rounded-lg p-5 space-y-4 bg-primary/5">
                    <div className="flex items-center gap-2">
                      <MessageSquare className="w-5 h-5 text-primary" />
                      <h4 className="font-semibold">Send Task to Agent</h4>
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1">Message</label>
                      <textarea
                        value={taskMessage}
                        onChange={(e) => setTaskMessage(e.target.value)}
                        placeholder="Enter a message to send as a task..."
                        rows={3}
                        className="w-full px-3 py-2 border rounded-lg bg-background focus:ring-2 focus:ring-primary focus:border-primary text-sm resize-none"
                      />
                    </div>
                    <button
                      onClick={sendTask}
                      disabled={taskLoading || !taskMessage}
                      className="w-full py-2.5 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
                    >
                      {taskLoading ? <><Loader2 className="w-4 h-4 animate-spin" />Sending...</> : <><Play className="w-4 h-4" />Send Task</>}
                    </button>

                    {taskError && (
                      <div className="p-3 border border-red-500 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 text-sm">{taskError}</div>
                    )}

                    {taskResult && (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h5 className="font-medium text-sm">Task Result</h5>
                          <button onClick={() => setShowTaskRaw(!showTaskRaw)} className="text-xs text-muted-foreground hover:text-foreground">
                            {showTaskRaw ? 'Hide' : 'Show'} Raw
                          </button>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Task ID: <span className="font-mono">{taskResult.taskId}</span>
                        </div>
                        <div className="border rounded-lg p-4 bg-background overflow-x-auto">
                          <pre className="text-xs font-mono whitespace-pre-wrap">
                            {JSON.stringify(showTaskRaw ? taskResult.raw : { status: taskResult.status, artifacts: taskResult.artifacts, history: taskResult.history }, null, 2)}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
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
                  <h3 className="font-semibold">A2A Agent Security Scan</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Analyzes your A2A agent card and endpoint for security vulnerabilities including prompt injection,
                  authentication issues, transport security, spec compliance, and information leakage.
                  Inspired by{' '}
                  <a href="https://github.com/cisco-ai-defense/a2a-scanner" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                    a2a-scanner
                  </a>.
                </p>
              </div>

              <button
                onClick={runSecurityScan}
                disabled={scanLoading || !agentCardUrl}
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
                      Agent: {scanReport.agentName} • {scanReport.skillsCount} skills • {scanReport.summary.total} findings
                    </p>
                  </div>

                  {/* Categories */}
                  {scanReport.categories.length > 0 && (
                    <div className="border rounded-lg overflow-hidden">
                      <div className="p-4 bg-muted">
                        <h4 className="font-medium">Categories Analyzed</h4>
                      </div>
                      <div className="divide-y">
                        {scanReport.categories.map((cat) => (
                          <div key={cat.name} className="flex items-center justify-between p-3">
                            <span className="text-sm">{cat.name}</span>
                            <span className={`text-xs font-mono ${cat.count > 0 ? 'text-red-600 dark:text-red-400 font-bold' : 'text-green-600 dark:text-green-400'}`}>
                              {cat.count} finding{cat.count !== 1 ? 's' : ''}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

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
                            <span className="text-xs text-muted-foreground">{finding.category}</span>
                            {getSecurityBadge(finding.severity)}
                          </div>
                          <h5 className="font-medium text-sm">{finding.title}</h5>
                          <p className="text-sm text-muted-foreground mt-1">{finding.description}</p>
                          {finding.evidence && (
                            <div className="mt-2 px-3 py-1.5 bg-muted rounded text-xs font-mono">
                              Evidence: {finding.evidence}
                            </div>
                          )}
                          {finding.recommendation && (
                            <div className="mt-2 text-xs text-primary">
                              Recommendation: {finding.recommendation}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Raw */}
                  <div className="border rounded-lg overflow-hidden">
                    <button onClick={() => setShowScanRaw(!showScanRaw)} className="w-full flex items-center justify-between p-4 bg-muted hover:bg-muted/80 transition-colors">
                      <span className="font-medium flex items-center gap-2"><Globe className="w-4 h-4" />Raw Scan Data</span>
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
