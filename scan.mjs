#!/usr/bin/env node

/**
 * Protocol Guard — CLI Scanner
 *
 * Run MCP or A2A security scans from the command line.
 * Designed for CI/CD pipelines (GitHub Actions, GitLab CI, etc.)
 *
 * Usage:
 *   node scan.mjs --type mcp --url https://your-mcp-server.com/mcp
 *   node scan.mjs --type a2a --url https://your-a2a-agent.com/
 *   node scan.mjs --type mcp --url https://server.com/mcp --auth bearer --token YOUR_TOKEN
 *   node scan.mjs --type mcp --url https://server.com/mcp --fail-on high
 *   node scan.mjs --type mcp --url https://server.com/mcp --custom-header "X-Org-Id:123" --custom-header "X-Env:prod"
 *
 * Options:
 *   --type            Scan type: "mcp" or "a2a" (required)
 *   --url             Target server/agent URL (required)
 *   --auth            Auth type: none, bearer, api_key, basic (default: none)
 *   --token           Auth token/value
 *   --header          Auth header name (default: Authorization)
 *   --custom-header   Extra header as "Key:Value" (repeatable)
 *   --fail-on         Exit with code 1 if findings at this severity or above
 *                     are found. Values: critical, high, medium, low, info (default: none)
 *   --json            Output raw JSON instead of formatted text
 *   --base-url        Protocol Guard instance URL (default: http://localhost:3000)
 *   --help            Show this help message
 *
 * Exit codes:
 *   0  Scan completed, no findings above threshold
 *   1  Scan completed, findings above threshold found
 *   2  Scan failed (connection error, invalid arguments, etc.)
 *
 * Open source — see LICENSE for details.
 *
 * @author Eduardo Arana & Soda
 */

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

function parseArgs(argv) {
  const args = {};
  const customHeaders = [];
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg === '--json') {
      args.json = true;
    } else if (arg === '--custom-header') {
      const val = argv[++i];
      if (val) {
        const colonIdx = val.indexOf(':');
        if (colonIdx > 0) {
          customHeaders.push({ key: val.slice(0, colonIdx).trim(), value: val.slice(colonIdx + 1).trim() });
        } else {
          console.error(`Warning: ignoring malformed --custom-header "${val}" (expected Key:Value)`);
        }
      }
    } else if (arg.startsWith('--')) {
      const key = arg.replace(/^--/, '').replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      args[key] = argv[++i];
    }
  }
  if (customHeaders.length > 0) {
    args.customHeaders = customHeaders;
  }
  return args;
}

function printUsage() {
  console.log(`
Protocol Guard — CLI Scanner

Usage:
  node scan.mjs --type <mcp|a2a> --url <target-url> [options]

Options:
  --type            Scan type: "mcp" or "a2a" (required)
  --url             Target server/agent URL (required)
  --auth            Auth type: none, bearer, api_key, basic (default: none)
  --token           Auth token/value
  --header          Auth header name (default: Authorization)
  --custom-header   Extra header as "Key:Value" (repeatable)
  --fail-on         Fail if findings at this severity or above exist
                    Values: critical, high, medium, low, info (default: none — never fail)
  --json            Output raw JSON instead of formatted text
  --base-url        Protocol Guard instance URL (default: http://localhost:3000)
  --help            Show this help message

Examples:
  # Scan an MCP server
  node scan.mjs --type mcp --url https://mcp.example.com/mcp

  # Scan an A2A agent with bearer auth
  node scan.mjs --type a2a --url https://agent.example.com/ --auth bearer --token sk-xxx

  # Fail CI if any high or critical findings
  node scan.mjs --type mcp --url https://mcp.example.com/mcp --fail-on high

  # Add custom headers to the scan
  node scan.mjs --type mcp --url https://mcp.example.com/mcp --custom-header "X-Org-Id:123" --custom-header "X-Env:prod"

  # Output JSON for programmatic consumption
  node scan.mjs --type mcp --url https://mcp.example.com/mcp --json

Exit codes:
  0  Scan completed, no findings above threshold
  1  Findings above threshold detected
  2  Scan error
`);
}

function severityIcon(sev) {
  switch (sev) {
    case 'critical': return '🔴';
    case 'high':     return '🟠';
    case 'medium':   return '🟡';
    case 'low':      return '🔵';
    case 'info':     return '⚪';
    default:         return '  ';
  }
}

function printReport(data, type) {
  const { findings = [], summary = {}, serverInfo, agentCard } = data;

  console.log('');
  console.log('═'.repeat(60));
  console.log(`  Protocol Guard — ${type.toUpperCase()} Security Scan Report`);
  console.log('═'.repeat(60));

  if (type === 'mcp' && serverInfo) {
    console.log(`  Server: ${serverInfo.name || 'unknown'} v${serverInfo.version || '?'}`);
    console.log(`  Tools:  ${data.toolsCount || 0}`);
  }
  if (type === 'a2a' && agentCard) {
    console.log(`  Agent:  ${agentCard.name || 'unknown'} v${agentCard.version || '?'}`);
    console.log(`  Skills: ${agentCard.skills?.length || 0}`);
  }

  console.log('─'.repeat(60));
  console.log(`  🔴 Critical: ${summary.critical || 0}  🟠 High: ${summary.high || 0}  🟡 Medium: ${summary.medium || 0}  🔵 Low: ${summary.low || 0}  ⚪ Info: ${summary.info || 0}`);
  console.log(`  Total findings: ${summary.total || findings.length}`);
  console.log('─'.repeat(60));

  if (findings.length === 0) {
    console.log('  ✅ No findings detected.');
  } else {
    for (const f of findings) {
      console.log('');
      console.log(`  ${severityIcon(f.severity)} [${f.severity.toUpperCase()}] ${f.title}`);
      if (f.owaspId) console.log(`    OWASP: ${f.owaspId} — ${f.owaspTitle || ''}`);
      if (f.category) console.log(`    Category: ${f.category}`);
      console.log(`    ${f.description}`);
      if (f.evidence) console.log(`    Evidence: ${f.evidence}`);
      if (f.recommendation) console.log(`    Fix: ${f.recommendation}`);
    }
  }

  console.log('');
  console.log('═'.repeat(60));
  console.log(`  Scan completed at ${data.timestamp || new Date().toISOString()}`);
  console.log('═'.repeat(60));
  console.log('');
}

function meetsThreshold(findings, threshold) {
  if (!threshold) return false;
  const thresholdIdx = SEVERITY_ORDER.indexOf(threshold);
  if (thresholdIdx < 0) return false;
  return findings.some(f => SEVERITY_ORDER.indexOf(f.severity) >= thresholdIdx);
}

async function runScan(args) {
  const baseUrl = (args.baseUrl || 'http://localhost:3000').replace(/\/+$/, '');
  const endpoint = args.type === 'mcp' ? '/api/mcp/security' : '/api/a2a/security';
  const url = baseUrl + endpoint;

  const body = args.type === 'mcp'
    ? {
        serverUrl: args.url,
        authType: args.auth || 'none',
        authValue: args.token || '',
        authHeader: args.header || 'Authorization',
        customHeaders: args.customHeaders || [],
      }
    : {
        agentUrl: args.url,
        authType: args.auth || 'none',
        authValue: args.token || '',
        authHeader: args.header || 'Authorization',
        customHeaders: args.customHeaders || [],
      };

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Scan request failed (HTTP ${response.status}): ${text}`);
  }

  return response.json();
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    printUsage();
    process.exit(0);
  }

  if (!args.type || !['mcp', 'a2a'].includes(args.type)) {
    console.error('Error: --type is required and must be "mcp" or "a2a"');
    printUsage();
    process.exit(2);
  }

  if (!args.url) {
    console.error('Error: --url is required');
    printUsage();
    process.exit(2);
  }

  try {
    const data = await runScan(args);

    if (data.error && !data.findings?.length) {
      console.error(`Scan error: ${data.error}`);
      process.exit(2);
    }

    if (args.json) {
      console.log(JSON.stringify(data, null, 2));
    } else {
      printReport(data, args.type);
    }

    const findings = data.findings || [];
    if (meetsThreshold(findings, args.failOn)) {
      const count = findings.filter(
        f => SEVERITY_ORDER.indexOf(f.severity) >= SEVERITY_ORDER.indexOf(args.failOn)
      ).length;
      if (!args.json) {
        console.error(`❌ ${count} finding(s) at ${args.failOn} severity or above — failing.`);
      }
      process.exit(1);
    }

    if (!args.json) {
      console.log('✅ Scan passed threshold check.');
    }
    process.exit(0);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(2);
  }
}

main();
