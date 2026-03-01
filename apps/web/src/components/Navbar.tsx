'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Terminal, Menu, X, Server, Globe, Key } from 'lucide-react';

const protocols = [
  { name: 'MCP', href: '/dashboard/mcp', icon: Server, color: 'text-blue-500' },
  { name: 'A2A', href: '/dashboard/a2a', icon: Globe, color: 'text-green-500' },
  { name: 'UCP', href: '/dashboard/ucp', icon: Key, color: 'text-amber-500' },
];

export function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  const isHome = pathname === '/';
  const isDashboard = pathname === '/dashboard';

  return (
    <header className="border-b border-border/50 backdrop-blur-md sticky top-0 z-50 bg-background/80">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-14">
          {/* Logo — always links home */}
          <Link href="/" className="flex items-center gap-2.5 shrink-0">
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
              <Terminal className="w-4 h-4 text-primary-foreground" />
            </div>
            <span className="font-bold text-base tracking-tight">Protocol Guard</span>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-1 ml-8">
            <Link
              href="/dashboard"
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                isDashboard
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted'
              }`}
            >
              Dashboard
            </Link>

            <div className="w-px h-5 bg-border mx-1" />

            {protocols.map((p) => {
              const Icon = p.icon;
              const isActive = pathname.startsWith(p.href);
              return (
                <Link
                  key={p.name}
                  href={p.href}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-primary' : p.color}`} />
                  {p.name}
                </Link>
              );
            })}
          </nav>

          {/* Right side */}
          <div className="flex items-center gap-2">
            {!isHome && (
              <Link
                href="/dashboard"
                className="hidden md:inline-flex px-3 py-1.5 text-xs font-medium border rounded-md hover:bg-muted transition-colors"
              >
                All Protocols
              </Link>
            )}
            <ThemeToggle />

            {/* Mobile hamburger */}
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="md:hidden p-2 rounded-lg hover:bg-muted transition-colors"
              aria-label="Toggle menu"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="md:hidden border-t border-border/50 bg-background/95 backdrop-blur-md">
          <nav className="container mx-auto px-4 py-3 flex flex-col gap-1">
            <Link
              href="/dashboard"
              onClick={() => setMobileOpen(false)}
              className={`flex items-center gap-2 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                isDashboard
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted'
              }`}
            >
              <Terminal className="w-4 h-4" />
              Dashboard
            </Link>

            <div className="h-px bg-border my-1" />

            {protocols.map((p) => {
              const Icon = p.icon;
              const isActive = pathname.startsWith(p.href);
              return (
                <Link
                  key={p.name}
                  href={p.href}
                  onClick={() => setMobileOpen(false)}
                  className={`flex items-center gap-2 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-primary' : p.color}`} />
                  {p.name} Testing
                </Link>
              );
            })}

            <div className="h-px bg-border my-1" />

            <Link
              href="/"
              onClick={() => setMobileOpen(false)}
              className="px-3 py-2.5 rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              Home
            </Link>
          </nav>
        </div>
      )}
    </header>
  );
}
