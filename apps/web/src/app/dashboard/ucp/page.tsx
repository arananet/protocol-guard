'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Navbar } from '@/components/Navbar';
import { ChevronDown, ChevronUp, ExternalLink, Key, CheckCircle, XCircle, AlertTriangle, Info, Server, ShoppingCart, EyeOff } from 'lucide-react';

type AuthType = 'none' | 'bearer' | 'basic' | 'api_key';

interface ComplianceResult {
  passed: boolean;
  ruleId: string;
  message: string;
  severity: 'critical' | 'warning' | 'info';
  docUrl?: string;
  details?: Record<string, unknown>;
}

interface ComplianceReport {
  timestamp: string;
  specVersion: string;
  specUrl: string;
  repoUrl: string;
  profileUrl: string;
  results: ComplianceResult[];
  passedCount: number;
  failedCount: number;
  warningCount: number;
  rawProfile?: Record<string, unknown> | null;
}

export default function UCPPage() {
  const [endpoint, setEndpoint] = useState('');
  const [authType, setAuthType] = useState<AuthType>('none');
  const [authValue, setAuthValue] = useState('');
  const [authHeader, setAuthHeader] = useState('Authorization');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [error, setError] = useState('');
  const [showRawProfile, setShowRawProfile] = useState(false);

  const runTest = async () => {
    if (!endpoint) return;
    setLoading(true);
    setError('');
    setReport(null);

    try {
      const response = await fetch('/api/ucp/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoint, authType, authValue, authHeader }),
      });

      if (!response.ok) {
        throw new Error('Failed to test UCP implementation');
      }

      const data = await response.json();
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed');
    } finally {
      setLoading(false);
    }
  };

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

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />

      <main className="flex-1 container mx-auto px-4 py-8">
        <div className="max-w-3xl mx-auto">
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-2">
              <ShoppingCart className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-bold">UCP Compliance Test</h2>
            </div>
            <p className="text-muted-foreground">
              Validate your <a href="https://ucp.dev" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Universal Commerce Protocol</a> business profile against the official specification. 
              UCP enables standardised commerce between businesses and platforms — co-developed by Google, Shopify, Etsy, Walmart, Target &amp; Wayfair.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
              <span>
                Spec version: <span className="font-mono font-bold">2026-01-23</span>
              </span>
              <span className="hidden sm:inline">·</span>
              <a href="https://ucp.dev/latest/specification/overview" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline flex items-center gap-1">
                Full Specification <ExternalLink className="w-3 h-3" />
              </a>
              <a href="https://github.com/Universal-Commerce-Protocol/ucp" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline flex items-center gap-1">
                GitHub <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>

          {/* How it works */}
          <div className="mb-6 p-4 border rounded-lg bg-muted/30 text-sm text-muted-foreground space-y-1">
            <p className="font-medium text-foreground">How it works</p>
            <p>1. Enter the base URL of the business (e.g. <code className="bg-muted px-1 rounded">https://shop.example.com</code>).</p>
            <p>2. We fetch <code className="bg-muted px-1 rounded">/.well-known/ucp</code> — the standard discovery endpoint.</p>
            <p>3. The returned JSON Business Profile is validated against 18 compliance rules covering profile structure, services, capabilities, namespaces, transports, payment handlers, signing keys, and security.</p>
            <p className="mt-2 pt-2 border-t border-border/50">You can also run Protocol Guard <strong className="text-foreground">locally via Docker</strong> or integrate the <strong className="text-foreground">CLI scanner into your CI/CD pipeline</strong> to gate deployments on compliance.</p>
          </div>

          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium mb-2">Business Base URL</label>
              <input
                type="text"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://shop.example.com"
                className="w-full px-4 py-2.5 border rounded-lg bg-background focus:ring-2 focus:ring-primary focus:border-primary"
              />
              <p className="mt-1 text-xs text-muted-foreground">We will fetch <code className="bg-muted px-1 rounded">{endpoint ? endpoint.replace(/\/+$/, '') : 'https://…'}/.well-known/ucp</code></p>
            </div>

            {/* Authentication Section */}
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

            <button
              onClick={runTest}
              disabled={loading || !endpoint}
              className="w-full py-3 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              {loading ? 'Scanning /.well-known/ucp...' : 'Run UCP Compliance Scan'}
            </button>
          </div>

          {/* No-storage notice */}
          <div className="mt-6 flex items-center gap-3 p-3 rounded-lg border border-primary/20 bg-primary/5">
            <EyeOff className="w-4 h-4 text-primary flex-shrink-0" />
            <p className="text-xs text-muted-foreground">
              <span className="font-medium text-foreground">No data stored.</span> URLs, credentials, and scan results are never saved. Everything runs in real-time and exists only in your browser session.
            </p>
          </div>

          {error && (
            <div className="mt-6 p-4 border border-red-500 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600">
              {error}
            </div>
          )}

          {report && (
            <div className="mt-8 space-y-6">
              {/* Protocol Info */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-sm">
                <div className="text-muted-foreground">
                  Spec: <span className="font-mono font-bold">{report.specVersion}</span>
                  <span className="mx-2">·</span>
                  Profile: <span className="font-mono text-xs">{report.profileUrl}</span>
                </div>
                <div className="flex items-center gap-3">
                  <a
                    href={report.specUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-primary hover:underline"
                  >
                    Spec <ExternalLink className="w-3 h-3" />
                  </a>
                  <a
                    href={report.repoUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-primary hover:underline"
                  >
                    Repo <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <h3 className="text-xl font-semibold">Compliance Report</h3>
                <div className="text-sm text-muted-foreground">
                  {new Date(report.timestamp).toLocaleString()}
                </div>
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

              {/* Raw Profile Viewer */}
              {report.rawProfile && (
                <div className="border rounded-lg overflow-hidden">
                  <button
                    onClick={() => setShowRawProfile(!showRawProfile)}
                    className="w-full flex items-center justify-between p-4 bg-muted hover:bg-muted/80 transition-colors"
                  >
                    <span className="font-medium flex items-center gap-2">
                      <Server className="w-4 h-4" />
                      Raw Business Profile
                    </span>
                    {showRawProfile ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                  {showRawProfile && (
                    <div className="p-4 bg-background overflow-x-auto">
                      <pre className="text-xs font-mono whitespace-pre-wrap">
                        {JSON.stringify(report.rawProfile, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* Results */}
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
                    {result.docUrl && !result.passed && (
                      <div className="mt-3 ml-7 flex items-center gap-2 px-3 py-2 rounded-md bg-muted/50 border border-border/50 w-fit">
                        <ExternalLink className="w-3.5 h-3.5 text-primary flex-shrink-0" />
                        <a
                          href={result.docUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-primary hover:underline font-medium"
                        >
                          UCP Specification Reference
                        </a>
                      </div>
                    )}
                  </div>
                ))}
              </div>
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
