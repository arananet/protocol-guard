'use client';

import { useState, useEffect, type ReactNode } from 'react';
import { AlertTriangle, ExternalLink, CheckSquare, Square } from 'lucide-react';

const STORAGE_KEY = 'protocol-guard-ack-accepted';

const ACKNOWLEDGMENTS: ReactNode[] = [
  'I understand this is an open-source community tool built for engineers, security researchers, and protocol developers',
  'I understand that no credentials, tokens, or secrets are stored anywhere — all values remain in the browser session and are never persisted',
  "I am solely responsible for the endpoints I test, the data I provide, and ensuring compliance with my organisation\u2019s policies",
  <>
    I understand the hosted version runs on{' '}
    <a href="https://railway.com/security" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-0.5">
      Railway <ExternalLink className="w-3 h-3" />
    </a>
    , but this tool can also be self-hosted via Docker or run locally
  </>,
  'I understand this tool is provided "as-is" without warranty of any kind — use at your own risk',
  'I acknowledge the hosted version uses Railway as a third-party platform; however, no logs, telemetry, or observability data are collected or tracked — you can verify this in the source code',
  'I am responsible for safeguarding my own API keys and credentials outside of this tool — Protocol Guard never transmits them to any backend or third-party service',
  'I understand there is no data retention — no secrets, scan results, or request payloads are sent to or stored in any backend system',
];

export function AcknowledgmentGate({ children }: { children: React.ReactNode }) {
  const [accepted, setAccepted] = useState<boolean | null>(null);
  const [checked, setChecked] = useState<boolean[]>(new Array(ACKNOWLEDGMENTS.length).fill(false));

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    setAccepted(stored === 'true');
  }, []);

  const allChecked = checked.every(Boolean);

  const handleAccept = () => {
    localStorage.setItem(STORAGE_KEY, 'true');
    setAccepted(true);
  };

  const toggleItem = (index: number) => {
    setChecked(prev => {
      const next = [...prev];
      next[index] = !next[index];
      return next;
    });
  };

  // Loading state — avoid flicker
  if (accepted === null) {
    return null;
  }

  if (accepted) {
    return <>{children}</>;
  }

  return (
    <div className="max-w-3xl mx-auto mt-8">
      <div className="rounded-xl border border-yellow-500/40 bg-yellow-50/50 dark:bg-yellow-950/20 p-6 shadow-sm">
        {/* Header */}
        <div className="flex items-start gap-3 mb-2">
          <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-400 mt-0.5 shrink-0" />
          <div>
            <h3 className="text-lg font-bold text-foreground">
              Before You Begin — Required Acknowledgment
            </h3>
            <p className="text-sm text-muted-foreground mt-0.5">
              Please review and accept the following items before using Protocol Guard
            </p>
          </div>
        </div>

        {/* Checklist */}
        <div className="mt-5 rounded-lg border border-border bg-background/60 dark:bg-background/40 divide-y divide-border">
          {ACKNOWLEDGMENTS.map((text, i) => (
            <button
              key={i}
              type="button"
              onClick={() => toggleItem(i)}
              className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-muted/40 transition-colors"
            >
              {checked[i] ? (
                <CheckSquare className="w-4 h-4 text-primary mt-0.5 shrink-0" />
              ) : (
                <Square className="w-4 h-4 text-muted-foreground mt-0.5 shrink-0" />
              )}
              <span className="text-sm text-foreground leading-snug">{text}</span>
            </button>
          ))}
        </div>

        {/* Footer */}
        <div className="mt-5 flex items-center justify-between">
          <p className="text-xs text-yellow-700 dark:text-yellow-400">
            You must accept all items to continue using this application
          </p>
          <button
            onClick={handleAccept}
            disabled={!allChecked}
            className="px-5 py-2 rounded-lg text-sm font-medium transition-colors
              bg-primary text-primary-foreground hover:bg-primary/90
              disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Accept All Terms
          </button>
        </div>
      </div>
    </div>
  );
}
