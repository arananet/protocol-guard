import type { Metadata } from 'next';
import './globals.css';
import { Providers } from './providers';

const siteUrl = 'https://protocol-guard.arananet.net';
const siteName = 'Protocol Guard';
const siteDescription =
  'Open-source compliance auditor and security scanner for MCP servers, A2A agents, and UCP business profiles. Validate protocol implementations against official specs and scan for OWASP vulnerabilities.';

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: 'Protocol Guard - MCP, A2A & UCP Compliance Testing and Security Scanning',
    template: '%s | Protocol Guard',
  },
  description: siteDescription,
  keywords: [
    'MCP',
    'Model Context Protocol',
    'A2A',
    'Agent-to-Agent',
    'UCP',
    'Universal Commerce Protocol',
    'compliance testing',
    'security scanning',
    'OWASP',
    'OWASP MCP Top 10',
    'protocol validation',
    'AI agent security',
    'MCP server testing',
    'A2A agent testing',
    'open source',
  ],
  authors: [{ name: 'Eduardo Arana' }],
  creator: 'Eduardo Arana',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: siteUrl,
    siteName,
    title: 'Protocol Guard - MCP, A2A & UCP Compliance Testing',
    description: siteDescription,
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Protocol Guard - MCP, A2A & UCP Compliance Testing',
    description: siteDescription,
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-snippet': -1,
      'max-image-preview': 'large',
    },
  },
  alternates: {
    canonical: siteUrl,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background font-sans antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
