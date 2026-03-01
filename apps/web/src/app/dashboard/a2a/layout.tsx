import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'A2A Agent Testing - Compliance, Interactive Testing & Security Scan',
  description:
    'Validate A2A (Agent-to-Agent) protocol agents against the official specification. Check agent cards, browse skills, send tasks, and scan for authentication, transport, and injection vulnerabilities.',
  alternates: {
    canonical: 'https://protocol-guard.arananet.net/dashboard/a2a',
  },
  openGraph: {
    title: 'A2A Agent Testing - Protocol Guard',
    description:
      'Compliance testing, agent card browser, task sending, and security scanning for Agent-to-Agent protocol implementations.',
  },
};

export default function A2ALayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
