import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'UCP Compliance Testing - Universal Commerce Protocol Validation',
  description:
    'Validate UCP (Universal Commerce Protocol) business profiles against the published specification at ucp.dev. 18 compliance rules covering services, capabilities, transport bindings, signing keys, and vendor namespaces.',
  alternates: {
    canonical: 'https://protocol-guard.arananet.net/dashboard/ucp',
  },
  openGraph: {
    title: 'UCP Compliance Testing - Protocol Guard',
    description:
      'Validate Universal Commerce Protocol business profiles served at /.well-known/ucp against the official ucp.dev specification.',
  },
};

export default function UCPLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
