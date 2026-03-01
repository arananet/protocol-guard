'use client';

import Link from 'next/link';
import { Navbar } from '@/components/Navbar';
import { Server, Globe, Key, Terminal, Shield, Play, Wrench, Zap } from 'lucide-react';

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />

      <main className="container mx-auto px-4 py-12">
        <h2 className="text-3xl font-bold mb-2">Protocol Testing Dashboard</h2>
        <p className="text-muted-foreground mb-8">Compliance testing, interactive exploration, and security scanning for AI protocols</p>
        
        {/* Protocol Cards */}
        <div className="grid md:grid-cols-3 gap-6">
          {/* MCP Testing */}
          <Link href="/dashboard/mcp" className="block group">
            <div className="p-6 border rounded-lg hover:border-primary hover:shadow-lg transition-all cursor-pointer h-full bg-card">
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                <Server className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-xl font-semibold mb-2">MCP Testing</h3>
              <p className="text-muted-foreground text-sm">
                Test your Model Context Protocol server. Compliance validation, interactive tool testing, and OWASP MCP Top 10 security scanning.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <span className="text-xs px-2 py-1 rounded bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 flex items-center gap-1"><Wrench className="w-3 h-3" />Compliance</span>
                <span className="text-xs px-2 py-1 rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 flex items-center gap-1"><Play className="w-3 h-3" />Interactive</span>
                <span className="text-xs px-2 py-1 rounded bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 flex items-center gap-1"><Shield className="w-3 h-3" />Security</span>
              </div>
              <div className="mt-3 text-sm text-primary font-medium flex items-center gap-1">
                Open MCP Dashboard →
              </div>
            </div>
          </Link>

          {/* A2A Testing */}
          <Link href="/dashboard/a2a" className="block group">
            <div className="p-6 border rounded-lg hover:border-primary hover:shadow-lg transition-all cursor-pointer h-full bg-card">
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                <Globe className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-xl font-semibold mb-2">A2A Testing</h3>
              <p className="text-muted-foreground text-sm">
                Validate Agent-to-Agent protocol agents. Compliance checks, skill exploration, task sending, and agent security scanning.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <span className="text-xs px-2 py-1 rounded bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 flex items-center gap-1"><Wrench className="w-3 h-3" />Compliance</span>
                <span className="text-xs px-2 py-1 rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 flex items-center gap-1"><Zap className="w-3 h-3" />Interactive</span>
                <span className="text-xs px-2 py-1 rounded bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 flex items-center gap-1"><Shield className="w-3 h-3" />Security</span>
              </div>
              <div className="mt-3 text-sm text-primary font-medium flex items-center gap-1">
                Open A2A Dashboard →
              </div>
            </div>
          </Link>

          {/* UCP Testing */}
          <Link href="/dashboard/ucp" className="block group">
            <div className="p-6 border rounded-lg hover:border-primary hover:shadow-lg transition-all cursor-pointer h-full bg-card">
              <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                <Key className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-xl font-semibold mb-2">UCP Compliance</h3>
              <p className="text-muted-foreground text-sm">
                Validate your UCP business profile (/.well-known/ucp) against the official specification — services, capabilities, namespaces, transports and more.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <span className="text-xs px-2 py-1 rounded bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 flex items-center gap-1"><Wrench className="w-3 h-3" />Compliance</span>
              </div>
              <div className="mt-3 text-sm text-primary font-medium flex items-center gap-1">
                Test Implementation →
              </div>
            </div>
          </Link>
        </div>

        {/* Features */}
        <div className="mt-12 grid md:grid-cols-3 gap-6">
          <div className="p-5 border rounded-lg bg-card">
            <div className="flex items-center gap-2 mb-3">
              <Wrench className="w-5 h-5 text-green-600 dark:text-green-400" />
              <h4 className="font-semibold">Compliance Testing</h4>
            </div>
            <p className="text-sm text-muted-foreground">
              Validate protocol implementations against official specifications. Check required fields, capabilities, and protocol adherence.
            </p>
          </div>
          <div className="p-5 border rounded-lg bg-card">
            <div className="flex items-center gap-2 mb-3">
              <Play className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              <h4 className="font-semibold">Interactive Testing</h4>
            </div>
            <p className="text-sm text-muted-foreground">
              Explore MCP server tools and call them with arguments. Discover A2A agent skills and send tasks. Live protocol interaction.
            </p>
          </div>
          <div className="p-5 border rounded-lg bg-card">
            <div className="flex items-center gap-2 mb-3">
              <Shield className="w-5 h-5 text-red-600 dark:text-red-400" />
              <h4 className="font-semibold">Security Scanning</h4>
            </div>
            <p className="text-sm text-muted-foreground">
              OWASP MCP Top 10 vulnerability detection for MCP servers. Agent card and endpoint security analysis for A2A agents.
            </p>
          </div>
        </div>

        {/* Stateless notice */}
        <div className="mt-8 p-4 border rounded-lg bg-muted/30 text-center">
          <p className="text-sm text-muted-foreground">
            <span className="font-medium">Fully stateless</span> — no URLs, credentials, or scan results are stored. All testing happens in real-time.
          </p>
        </div>
      </main>

      <footer className="border-t py-6">
        <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              © 2026 Protocol Guard. Built by Eduardo Arana & Soda 🥤
            </p>
          </div>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <a href="https://github.com/arananet/protocol-guard" target="_blank" rel="noopener noreferrer" className="hover:text-foreground">Open Source on GitHub</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
