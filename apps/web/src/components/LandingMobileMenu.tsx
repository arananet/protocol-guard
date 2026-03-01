'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Menu, X, Server, Globe, Key, ArrowRight } from 'lucide-react';

export function LandingMobileMenu() {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        onClick={() => setOpen(!open)}
        className="p-2 rounded-lg hover:bg-muted transition-colors"
        aria-label="Toggle menu"
      >
        {open ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {open && (
        <div className="absolute top-14 left-0 right-0 border-b border-border/50 bg-background/95 backdrop-blur-md z-50">
          <nav className="container mx-auto px-4 py-3 flex flex-col gap-1">
            <Link
              href="#features"
              onClick={() => setOpen(false)}
              className="px-3 py-2.5 rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              Features
            </Link>
            <Link
              href="#enterprise"
              onClick={() => setOpen(false)}
              className="px-3 py-2.5 rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              Enterprise
            </Link>

            <div className="h-px bg-border my-1" />

            <Link
              href="/dashboard/mcp"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-3 py-2.5 rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              <Server className="w-4 h-4 text-blue-500" />
              MCP Testing
            </Link>
            <Link
              href="/dashboard/a2a"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-3 py-2.5 rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              <Globe className="w-4 h-4 text-green-500" />
              A2A Testing
            </Link>
            <Link
              href="/dashboard/ucp"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-3 py-2.5 rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              <Key className="w-4 h-4 text-amber-500" />
              UCP Testing
            </Link>

            <div className="h-px bg-border my-1" />

            <Link
              href="/dashboard"
              onClick={() => setOpen(false)}
              className="flex items-center justify-center gap-2 px-3 py-2.5 rounded-md text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              Get Started
              <ArrowRight className="w-4 h-4" />
            </Link>
          </nav>
        </div>
      )}
    </>
  );
}
