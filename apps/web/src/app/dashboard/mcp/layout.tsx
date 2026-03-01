import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'MCP Server Testing - Compliance, Interactive Testing & OWASP Security Scan',
  description:
    'Validate MCP (Model Context Protocol) servers against the official specification. Run compliance checks, explore tools interactively, and scan for all 10 OWASP MCP Top 10 vulnerabilities.',
  alternates: {
    canonical: 'https://protocol-guard.arananet.net/dashboard/mcp',
  },
  openGraph: {
    title: 'MCP Server Testing - Protocol Guard',
    description:
      'Compliance testing, interactive tool explorer, and OWASP MCP Top 10 security scanning for Model Context Protocol servers.',
  },
};

export default function MCPLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
