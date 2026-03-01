import Link from 'next/link';
import { Shield, Zap, Lock, CheckCircle, ArrowRight, Server, Key, Globe, BadgeCheck, TrendingUp, Users } from 'lucide-react';

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Header - Clean Corporate */}
      <header className="border-b border-border bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-primary rounded-md flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-navy">Protocol Guard</h1>
              <p className="text-xs text-muted-foreground -mt-0.5">Enterprise Compliance</p>
            </div>
          </div>
          <nav className="flex items-center gap-8">
            <Link href="#features" className="text-sm text-muted-foreground hover:text-primary transition-colors">
              Features
            </Link>
            <Link href="#pricing" className="text-sm text-muted-foreground hover:text-primary transition-colors">
              Pricing
            </Link>
            <Link href="/dashboard" className="text-sm font-medium text-primary hover:text-primary/80 transition-colors">
              Sign In
            </Link>
            <Link
              href="/dashboard"
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors shadow-sm"
            >
              Get Started
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero - Clean & Professional */}
      <main className="flex-1">
        <section className="relative">
          <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent" />
          
          <div className="container mx-auto px-4 py-24 md:py-28">
            <div className="max-w-3xl mx-auto text-center">
              {/* Trust Badge */}
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6">
                <BadgeCheck className="w-4 h-4" />
                <span>Trusted by 500+ Development Teams</span>
              </div>
              
              <h2 className="text-4xl md:text-5xl font-bold text-navy mb-6 leading-tight">
                Protocol Compliance,
                <br />
                <span className="text-primary">Simplified</span>
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-8 leading-relaxed">
                Automatically validate your MCP, A2A, and UCP implementations against 
                official specifications. Catch issues before they reach production.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                <Link
                  href="/dashboard"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-md text-base font-medium hover:bg-primary/90 transition-colors shadow-sm"
                >
                  Start Free Trial
                  <ArrowRight className="w-4 h-4" />
                </Link>
                <Link
                  href="#demo"
                  className="inline-flex items-center gap-2 px-6 py-3 border border-border bg-white text-base font-medium rounded-md hover:bg-secondary transition-colors"
                >
                  View Demo
                </Link>
              </div>
              
              {/* Stats */}
              <div className="mt-12 grid grid-cols-3 gap-8 max-w-lg mx-auto">
                <div>
                  <div className="text-2xl font-bold text-navy">10K+</div>
                  <div className="text-xs text-muted-foreground">Tests Run</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-navy">500+</div>
                  <div className="text-xs text-muted-foreground">Vendors Audited</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-navy">3</div>
                  <div className="text-xs text-muted-foreground">Protocols</div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Protocol Cards - Clean Grid */}
        <section className="py-16 bg-secondary/30">
          <div className="container mx-auto px-4">
            <div className="text-center mb-10">
              <h3 className="text-2xl font-bold text-navy mb-2">Supported Protocols</h3>
              <p className="text-muted-foreground">Comprehensive testing for major agent protocols</p>
            </div>
            
            <div className="grid md:grid-cols-3 gap-6 max-w-4xl mx-auto">
              {/* MCP */}
              <div className="bg-white rounded-lg border border-border p-6 shadow-enterprise hover:shadow-enterprise-lg transition-shadow">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-blue-50 rounded-md flex items-center justify-center">
                    <Server className="w-5 h-5 text-blue-600" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-navy">MCP</h4>
                    <p className="text-xs text-muted-foreground">Model Context Protocol</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Validate tools, resources, prompts, and authentication implementations.
                </p>
                <ul className="space-y-2">
                  {['Tools & Resources', 'Prompts', 'Auth (API Key/OAuth)', 'Extensions'].map((item, i) => (
                    <li key={i} className="flex items-center gap-2 text-sm">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* A2A */}
              <div className="bg-white rounded-lg border border-border p-6 shadow-enterprise hover:shadow-enterprise-lg transition-shadow">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-purple-50 rounded-md flex items-center justify-center">
                    <Globe className="w-5 h-5 text-purple-600" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-navy">A2A</h4>
                    <p className="text-xs text-muted-foreground">Agent-to-Agent Protocol</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Verify agent cards, task workflows, and messaging compliance.
                </p>
                <ul className="space-y-2">
                  {['Agent Cards', 'Task Management', 'Streaming', 'Push Notifications'].map((item, i) => (
                    <li key={i} className="flex items-center gap-2 text-sm">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* UCP */}
              <div className="bg-white rounded-lg border border-border p-6 shadow-enterprise hover:shadow-enterprise-lg transition-shadow">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-green-50 rounded-md flex items-center justify-center">
                    <Key className="w-5 h-5 text-green-600" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-navy">UCP</h4>
                    <p className="text-xs text-muted-foreground">Commerce Protocol</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Validate UCP business profiles against the official specification from ucp.dev.
                </p>
                <ul className="space-y-2">
                  {['Profile Discovery', 'Namespace Validation', 'Transport Bindings', 'Payment Handlers'].map((item, i) => (
                    <li key={i} className="flex items-center gap-2 text-sm">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Features - Clean List */}
        <section id="features" className="py-20">
          <div className="container mx-auto px-4">
            <div className="max-w-3xl mx-auto">
              <div className="text-center mb-12">
                <h3 className="text-2xl font-bold text-navy mb-2">Enterprise Features</h3>
                <p className="text-muted-foreground">Everything you need for protocol compliance</p>
              </div>
              
              <div className="grid md:grid-cols-2 gap-6">
                {[
                  { icon: Zap, title: 'Instant Validation', desc: 'Run comprehensive tests in seconds, not hours' },
                  { icon: CheckCircle, title: 'Clear Results', desc: 'Specific pass/fail with detailed error reporting' },
                  { icon: Server, title: 'CI/CD Integration', desc: 'Automated testing in your deployment pipeline' },
                  { icon: Key, title: 'API Access', desc: 'Programmatic access for custom workflows' },
                  { icon: Users, title: 'Team Collaboration', desc: 'Share results, assign tasks, track progress' },
                  { icon: TrendingUp, title: 'Historical Reports', desc: 'Track compliance over time with trends' },
                ].map((feature, i) => (
                  <div key={i} className="flex gap-4 p-4 bg-white rounded-lg border border-border">
                    <div className="w-10 h-10 bg-secondary rounded-md flex items-center justify-center flex-shrink-0">
                      <feature.icon className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-navy mb-1">{feature.title}</h4>
                      <p className="text-sm text-muted-foreground">{feature.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Enterprise Maturity Assessment */}
        <section className="py-16 bg-navy text-white">
          <div className="container mx-auto px-4">
            <div className="max-w-3xl mx-auto text-center">
              <h3 className="text-2xl font-bold mb-3">Enterprise Maturity Assessment</h3>
              <p className="text-white/70 mb-8 max-w-xl mx-auto">
                Evaluate whether your vendors&apos; protocol implementations meet enterprise-grade requirements
              </p>
              <div className="grid md:grid-cols-3 gap-8">
                {[
                  { icon: Shield, title: 'Protocol Conformance' },
                  { icon: Lock, title: 'Security Posture' },
                  { icon: CheckCircle, title: 'Audit Trail' },
                ].map((item, i) => (
                  <div key={i} className="flex flex-col items-center">
                    <div className="w-12 h-12 bg-white/10 rounded-full flex items-center justify-center mb-3">
                      <item.icon className="w-5 h-5" />
                    </div>
                    <div className="font-medium">{item.title}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-20">
          <div className="container mx-auto px-4">
            <div className="max-w-2xl mx-auto text-center bg-gradient-to-br from-primary/5 to-primary/10 rounded-2xl p-8 md:p-12 border border-primary/10">
              <h3 className="text-2xl font-bold text-navy mb-4">Start Your Free Trial</h3>
              <p className="text-muted-foreground mb-6">
                No credit card required. 14-day free trial with full features.
              </p>
              <Link
                href="/dashboard"
                className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-md text-base font-medium hover:bg-primary/90 transition-colors shadow-sm"
              >
                Get Started
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t bg-white py-8">
        <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              © 2026 Protocol Guard. Built by Eduardo Arana & Soda 🥤
            </p>
          </div>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <Link href="#" className="hover:text-primary transition-colors">Privacy</Link>
            <Link href="#" className="hover:text-primary transition-colors">Terms</Link>
            <Link href="#" className="hover:text-primary transition-colors">Contact</Link>
            <Link href="https://github.com/arananet/protocol-guard" className="hover:text-primary transition-colors">Open Source on GitHub</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
