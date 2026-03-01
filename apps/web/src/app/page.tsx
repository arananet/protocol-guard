import Link from 'next/link';
import { ThemeToggle } from '@/components/ThemeToggle';
import { LandingMobileMenu } from '@/components/LandingMobileMenu';
import { Shield, Zap, Lock, CheckCircle, ArrowRight, Terminal, Cpu, Globe, Server, Key, EyeOff } from 'lucide-react';

const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'Protocol Guard',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Web',
  url: 'https://protocol-guard.arananet.net',
  description:
    'Open-source compliance auditor and security scanner for MCP servers, A2A agents, and UCP business profiles. Validate implementations against official protocol specs and scan for OWASP vulnerabilities.',
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
  author: {
    '@type': 'Person',
    name: 'Eduardo Arana',
  },
  license: 'https://opensource.org/licenses/MIT',
  isAccessibleForFree: true,
  featureList: [
    'MCP server compliance testing against official specification',
    'A2A agent card compliance validation',
    'UCP business profile compliance with 18 rules',
    'OWASP MCP Top 10 security scanning',
    'A2A security scanning with 8 vulnerability categories',
    'Interactive MCP tool testing',
    'Interactive A2A task sending',
    'CLI scanner for CI/CD pipelines',
    'Docker support',
  ],
};

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col bg-background">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      {/* Header */}
      <header className="border-b border-border/50 backdrop-blur-md sticky top-0 z-50 bg-background/80">
        <div className="container mx-auto px-4 h-14 flex items-center justify-between">
          <Link href="/dashboard" className="flex items-center gap-2.5 shrink-0">
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
              <Terminal className="w-4 h-4 text-primary-foreground" />
            </div>
            <div>
              <span className="font-bold text-base tracking-tight">Protocol Guard</span>
              <p className="text-[10px] text-muted-foreground -mt-0.5 hidden sm:block">Compliance Tester</p>
            </div>
          </Link>
          <nav className="hidden md:flex items-center gap-6">
            <Link href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              Features
            </Link>
            <Link href="#enterprise" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              Enterprise
            </Link>
            <Link href="/dashboard" className="text-sm font-medium hover:text-primary transition-colors">
              Dashboard
            </Link>
            <ThemeToggle />
            <Link
              href="/dashboard"
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
            >
              Get Started
            </Link>
          </nav>
          <div className="flex md:hidden items-center gap-2">
            <ThemeToggle />
            <LandingMobileMenu />
          </div>
        </div>
      </header>

      {/* Hero */}
      <main className="flex-1">
        <section className="relative overflow-hidden">
          {/* Background Pattern */}
          <div className="absolute inset-0 bg-dot-pattern opacity-50" />
          <div className="absolute inset-0 bg-gradient-to-b from-transparent via-background/50 to-background" />
          
          <div className="container mx-auto px-4 py-24 md:py-32 relative">
            <div className="max-w-4xl mx-auto text-center">
              {/* Badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm mb-8">
                <Zap className="w-4 h-4" />
                <span>Now supporting UCP Protocol</span>
              </div>
              
              <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6 leading-tight">
                Validate Protocol Compliance
                <br />
                <span className="text-gradient-cyan">Before Production</span>
              </h1>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed">
                Test your MCP, A2A, and UCP implementations against official specifications. 
                Detect non-compliance and OWASP vulnerabilities before they reach production.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Link
                  href="/dashboard"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-lg text-base font-medium hover:bg-primary/90 transition-all hover:shadow-lg hover:shadow-primary/20 group"
                >
                  Start Testing
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </Link>
                <Link
                  href="#features"
                  className="inline-flex items-center gap-2 px-6 py-3 border border-border rounded-lg text-base font-medium hover:bg-secondary transition-colors"
                >
                  Learn More
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* Protocol Cards */}
        <section className="py-16 border-y border-border/30 bg-card/30">
          <div className="container mx-auto px-4">
            <div className="grid md:grid-cols-3 gap-6">
              {/* MCP */}
              <Link href="/dashboard/mcp" className="group block">
                <div className="p-6 rounded-xl border border-border bg-card hover:border-primary/50 transition-all hover:shadow-lg h-full">
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                    <Cpu className="w-6 h-6 text-primary" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">MCP Compliance</h3>
                  <p className="text-sm text-muted-foreground">
                    Validate Model Context Protocol. Test tools, resources, prompts, and authentication.
                  </p>
                  <div className="mt-4 flex items-center text-sm text-primary font-medium">
                    <span>Test now</span>
                    <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
                  </div>
                </div>
              </Link>

              {/* A2A */}
              <Link href="/dashboard/a2a" className="group block">
                <div className="p-6 rounded-xl border border-border bg-card hover:border-primary/50 transition-all hover:shadow-lg h-full">
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                    <Globe className="w-6 h-6 text-primary" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">A2A Compliance</h3>
                  <p className="text-sm text-muted-foreground">
                    Verify Agent-to-Agent implementations. Validate agent cards and task workflows.
                  </p>
                  <div className="mt-4 flex items-center text-sm text-primary font-medium">
                    <span>Test now</span>
                    <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
                  </div>
                </div>
              </Link>

              {/* Auth */}
              <Link href="/dashboard/ucp" className="group block">
                <div className="p-6 rounded-xl border border-border bg-card hover:border-primary/50 transition-all hover:shadow-lg h-full">
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                    <Key className="w-6 h-6 text-primary" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">UCP Compliance</h3>
                  <p className="text-sm text-muted-foreground">
                    Validate UCP business profiles at /.well-known/ucp against the official specification.
                  </p>
                  <div className="mt-4 flex items-center text-sm text-primary font-medium">
                    <span>Test now</span>
                    <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
                  </div>
                </div>
              </Link>
            </div>
          </div>
        </section>

        {/* Features */}
        <section id="features" className="py-20">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">Why Protocol Guard?</h2>
              <p className="text-muted-foreground max-w-xl mx-auto">
                Built for developers who care about standards compliance
              </p>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              {[
                { icon: Shield, title: 'Comprehensive Testing', desc: 'Test against full protocol specifications, not just happy paths' },
                { icon: Zap, title: 'Instant Results', desc: 'Get detailed compliance reports in seconds, not hours' },
                { icon: CheckCircle, title: 'Clear Pass/Fail', desc: 'Unambiguous results with specific failure points' },
                { icon: Terminal, title: 'Developer First', desc: 'CLI tools, API access, and CI/CD integrations' },
                { icon: Lock, title: 'Secure Testing', desc: 'Your implementations never leave your infrastructure' },
                { icon: EyeOff, title: 'Zero Data Storage', desc: 'No URLs, credentials, or scan results are ever stored. Fully stateless — every test runs in real-time and nothing is persisted' },
                { icon: Server, title: 'Multi-Protocol', desc: 'MCP, A2A, and UCP support out of the box' },
              ].map((feature, i) => (
                <div key={i} className="flex gap-4 p-4">
                  <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center flex-shrink-0">
                    <feature.icon className="w-5 h-5 text-muted-foreground" />
                  </div>
                  <div>
                    <h3 className="font-semibold mb-1">{feature.title}</h3>
                    <p className="text-sm text-muted-foreground">{feature.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Enterprise Maturity Assessment */}
        <section id="enterprise" className="py-20 bg-card/50 border-y border-border/30">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">Enterprise Maturity Assessment</h2>
              <p className="text-muted-foreground max-w-2xl mx-auto">
                Evaluate whether your vendors&apos; MCP, A2A, and UCP implementations meet enterprise-grade requirements.
                Identify gaps before they become risks.
              </p>
            </div>
            <div className="grid md:grid-cols-3 gap-6 max-w-4xl mx-auto">
              {[
                { icon: Shield, title: 'Protocol Conformance', desc: 'Verify implementations match official protocol specifications and required fields' },
                { icon: CheckCircle, title: 'Security Posture', desc: 'Audit authentication schemes, encryption, and access control configurations' },
                { icon: Lock, title: 'Audit Trail', desc: 'Full compliance reporting with traceability to specification references' },
              ].map((item, i) => (
                <div key={i} className="p-6 rounded-xl border border-border bg-card text-center">
                  <div className="w-12 h-12 mx-auto mb-4 rounded-lg bg-primary/10 flex items-center justify-center">
                    <item.icon className="w-5 h-5 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">{item.title}</h3>
                  <p className="text-sm text-muted-foreground">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Privacy Banner */}
        <section className="py-10">
          <div className="container mx-auto px-4">
            <div className="max-w-3xl mx-auto flex items-center gap-4 p-5 rounded-xl border border-primary/20 bg-primary/5">
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                <EyeOff className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h3 className="font-semibold text-sm mb-0.5">No Data Storage — Ever</h3>
                <p className="text-sm text-muted-foreground">
                  Protocol Guard is fully stateless. We never store URLs, credentials, tokens, scan results, or any information you enter. All tests run in real-time and results exist only in your browser session.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Run Anywhere */}
        <section className="py-20">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">Run Anywhere</h2>
              <p className="text-muted-foreground max-w-2xl mx-auto">
                Use Protocol Guard in the way that fits your workflow
              </p>
            </div>
            <div className="grid md:grid-cols-3 gap-6 max-w-4xl mx-auto">
              <div className="p-6 rounded-xl border border-border bg-card text-center">
                <div className="w-12 h-12 mx-auto mb-4 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">Hosted</h3>
                <p className="text-sm text-muted-foreground">Use the hosted version at <span className="font-mono text-xs">protocol-guard.arananet.net</span> — no setup required.</p>
              </div>
              <div className="p-6 rounded-xl border border-border bg-card text-center">
                <div className="w-12 h-12 mx-auto mb-4 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Server className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">Docker</h3>
                <p className="text-sm text-muted-foreground">Run locally with <span className="font-mono text-xs">docker compose up</span>. Everything stays on your machine — ideal for air-gapped or private environments.</p>
              </div>
              <div className="p-6 rounded-xl border border-border bg-card text-center">
                <div className="w-12 h-12 mx-auto mb-4 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Terminal className="w-5 h-5 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">CI/CD</h3>
                <p className="text-sm text-muted-foreground">Add the CLI scanner to your GitHub Actions, GitLab CI, or any pipeline to gate deployments on protocol compliance.</p>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-20 relative overflow-hidden">
          <div className="absolute inset-0 bg-dot-pattern opacity-30" />
          <div className="container mx-auto px-4 relative">
            <div className="max-w-2xl mx-auto text-center">
              <h2 className="text-3xl font-bold mb-4">Ready to validate?</h2>
              <p className="text-muted-foreground mb-8">
                Start testing your protocol implementations today. Free tier available.
              </p>
              <Link
                href="/dashboard"
                className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-lg text-base font-medium hover:bg-primary/90 transition-all hover:shadow-lg hover:shadow-primary/20"
              >
                Get Started Free
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-border py-8">
        <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              © 2026 Protocol Guard. Built by Eduardo Arana & Soda 🥤
            </p>
          </div>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <Link href="#" className="hover:text-foreground transition-colors">Privacy</Link>
            <Link href="#" className="hover:text-foreground transition-colors">Terms</Link>
            <Link href="https://github.com/arananet/protocol-guard" className="hover:text-foreground transition-colors">Open Source on GitHub</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
