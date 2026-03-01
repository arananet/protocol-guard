import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Dashboard',
  description:
    'Test MCP servers, A2A agents, and UCP business profiles for compliance and security vulnerabilities. Run real-time scans against official protocol specifications.',
  alternates: {
    canonical: 'https://protocol-guard.arananet.net/dashboard',
  },
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
