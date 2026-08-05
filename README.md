# Protocol Guard

**Open-source** platform for testing, exploring, and security-scanning MCP (Model Context Protocol) and A2A (Agent-to-Agent) protocol implementations.

> **Fully stateless** — no URLs, credentials, tokens, or scan results are ever stored. All tests run in real-time and results exist only in your browser session.

> **Transparent by design** — this project is open source so you can inspect exactly what every scan does. The source code is the documentation. We believe security tools should never be black boxes.

## Open Source

Protocol Guard is released under the **MIT License**. You are free to use, modify, and distribute this software. The only thing we ask is that you **respect the original authors** — keep attribution in your forks and don't misrepresent the origin of the work.

See [LICENSE](LICENSE) for the full license text.

## Features

### Compliance Testing
- **MCP Compliance** — validate MCP server implementations against the official specification, currently [`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28). That revision turned MCP into a **stateless request/response protocol**, so the scanner is dual-era: it probes `server/discover` at the current revision first and falls back to the `initialize` handshake only for servers on `2025-11-25` and earlier, then grades each server against the rules for its own era.

  | Era | What is checked |
  |-----|-----------------|
  | Stateless (`2026-07-28`) | `server/discover` is implemented (a MUST) and advertises `supportedVersions`; server identity in each result's `_meta`; required `resultType` on results; `ttlMs` + `cacheScope` cache hints on `tools/list`; server-side validation of the mirrored `Mcp-Method` / `Mcp-Name` headers (expects `400` + `HeaderMismatch` `-32020`); statelessness (no `Mcp-Session-Id` minted, `GET` not served); deprecated Roots / Sampling / Logging capabilities |
  | Handshake (`≤ 2025-11-25`) | `initialize` and `notifications/initialized`, `ping`, capabilities, server info — plus a warning that the revision is superseded, and whether the server also answers `server/discover` (dual-era) |

  Both eras are checked for **deprecated revisions** (`2024-11-05`, `2025-03-26`) that predate the OAuth Resource Server model and Resource Indicators (RFC 8707).
- **A2A Compliance** — verify A2A agent cards against the current spec (`0.3.0`). Resolves the canonical `/.well-known/agent-card.json` (with legacy `/.well-known/agent.json` fallback) and validates required fields, `protocolVersion`, skills, input/output modes, capabilities, **transport declarations** (`preferredTransport`/`additionalInterfaces`: JSONRPC, GRPC, HTTP+JSON), modern **`securitySchemes`/`security`** (with legacy `authentication` fallback), and **JWS card signatures** (`AgentCardSignature`).
- **UCP Compliance** — 18 compliance rules validating UCP business profiles against the [published specification](https://ucp.dev/latest/specification/overview) (profile structure, services, capabilities, transport bindings, signing keys, vendor namespaces)

### Interactive Testing
- **MCP Tool Explorer** — list all available tools on an MCP server and call any tool with custom arguments. Calls are made in the server's own era: against a stateless server the explorer mirrors `Mcp-Method`, `Mcp-Name` and any `x-mcp-header`-annotated parameters into HTTP headers, rejects tools whose annotations violate the spec, and surfaces a multi round-trip `input_required` result (with its `inputRequests`) instead of treating it as tool output
- **A2A Skill Browser** — fetch agent cards, browse declared skills with tags/examples, and send tasks to agents

### Security Scanning
- **MCP OWASP Top 10 Scanner** — detects all 10 [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) vulnerability categories (MCP01–MCP10) including tool poisoning, command injection, privilege escalation, and context injection. Detection patterns inspired by [mcp-shield](https://github.com/riseandignite/mcp-shield).
- **MCP MSSS v0.1 Coverage** — layered on top of the OWASP scan, each finding is cross-referenced against the [MCP Server Security Standard (MSSS)](https://github.com/mcp-security-standard/mcp-server-security-standard) where applicable. The scanner evaluates the following remotely-detectable controls:

  | Control | Level | What is checked |
  |---------|-------|-----------------|
  | `MCP-INPUT-01` | L1 | Tools missing `inputSchema` or with `additionalProperties` not set to `false` (schema poisoning risk) |
  | `MCP-INPUT-02` | L2 | String parameters without `maxLength` and arrays without `maxItems` (DoS / ReDoS risk) |
  | `MCP-NET-01` | L1 | URL-type parameters (`url`, `endpoint`, `webhook`, …) with no `pattern`/`enum` constraint (SSRF risk) |
  | `MCP-FS-01` | L1 | Path/file parameters without a `pattern` constraint (path traversal risk) |
  | `MCP-FS-02` | L1 | Symlink/readlink references in tool descriptions (symlink traversal risk) |
  | `MCP-EXEC-03` | L2 | Command/argument parameters without an `enum` allowlist (argument injection risk) |

  Each finding that maps to a MSSS control includes `msssId` and `msssLevel` fields. The scan response also includes a `msssControls` coverage block alongside the existing `owaspCoverage` block.

- **MCP Spec & Authorization Hardening** — on top of OWASP/MSSS, the scanner audits the security-relevant additions of the recent MCP revisions:

  | Check | What is evaluated |
  |-------|-------------------|
  | Protocol version | Negotiated revision is current; deprecated revisions (no Resource Indicators / OAuth Resource Server model) are flagged, as is a superseded handshake-era revision and a stateless server that does not answer `server/discover` |
  | OAuth 2.1 metadata | Probes `/.well-known/oauth-protected-resource` (RFC 9728) and inspects the `WWW-Authenticate` challenge for a `resource_metadata` pointer; flags openly-accessible servers |
  | Authorization server | Fetches the authorization server's metadata and flags missing **RFC 9207** issuer identification (`authorization_response_iss_parameter_supported`, the mix-up defence) and reliance on **deprecated Dynamic Client Registration** where **Client ID Metadata Documents** (`client_id_metadata_document_supported`) are not offered (2026-07-28) |
  | Statelessness | Servers that still mint an `Mcp-Session-Id`, or still serve a standalone SSE stream on `GET`, after protocol-level sessions and the GET endpoint were removed (2026-07-28) |
  | Deprecated features | Roots, Sampling and Logging capabilities, Deprecated as of 2026-07-28 with a twelve-month removal window |
  | Header mirroring | `x-mcp-header` annotations that violate the spec's constraints (empty, non-token, CR/LF, duplicate, non-primitive, not statically reachable — such tools MUST be rejected by clients), and parameters mirrored into credential-shaped headers (`Authorization`, `Cookie`, API keys, forwarding headers) where the value becomes visible to every proxy on the path (2026-07-28) |
  | Cache hints | `cacheScope: "public"` on an authenticated server — which lets a shared gateway serve one caller's response to another — and missing/invalid `ttlMs` + `cacheScope` on cacheable results (2026-07-28) |
  | Schema supply chain | Network (`http(s)://`) `$ref` targets in tool `inputSchema`/`outputSchema`, which implementations MUST NOT dereference automatically (2026-07-28) |
  | Tool annotations | State-changing tools missing `ToolAnnotations`, and misleading `readOnlyHint` on mutating tools (2025-06-18+) |
  | Resources & prompts | `resources/list` and `prompts/list` are scanned for `file://` exposure, sensitive locations, and hidden-instruction / intent-subversion poisoning |
  | Lethal trifecta | Servers that co-locate untrusted-input ingestion, private-data access, and outbound communication (prompt-injection exfiltration risk) |

- **MCP Apps (interactive UI) Scanner** — detects the [MCP Apps extension](https://github.com/modelcontextprotocol/ext-apps) (SEP-1865): `ui://` resources, `text/html` resources, and tools linked to UI templates via `_meta`. Flags the host-side obligations (sandboxed iframe rendering, CSP from resource metadata, auditable `postMessage` JSON-RPC, explicit consent for UI-initiated tool calls), external-origin UI assets, and hidden instructions embedded in UI markup.

- **A2A Security Scanner** — multi-category analysis covering spec compliance, **modern `securitySchemes`/`security`** (apiKey-in-query and HTTP Basic weaknesses, declared-but-unreferenced schemes), **JWS agent-card signatures** (presence, `alg: none`, missing `kid`), **transport bindings** (HTTP-over-plaintext interface endpoints, unknown transports), **declared extensions** including the **A2A UI / A2UI** extension (untrusted server-driven UI rendering), auxiliary URLs (`iconUrl`/`documentationUrl`), legacy well-known-path detection, injection risks, secret leakage, and security headers. Scan approach inspired by [a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner).

### Privacy
- Zero data storage — nothing is ever persisted
- No database, no local storage, no cookies for user data
- Every scan is ephemeral and runs entirely in the browser session

## Tech Stack

- **Frontend**: Next.js 14 (App Router), TypeScript, Tailwind CSS
- **Backend**: Next.js API Routes
- **Styling**: Tailwind CSS with HSL CSS variables, dark/light theme
- **Icons**: Lucide React
- **Monorepo**: pnpm workspaces + Turborepo
- **Testing**: Vitest

## Getting Started

### Prerequisites

- Node.js 20+
- pnpm 9+

### Installation

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev
```

### Production

```bash
# Build for production
pnpm build

# Start production server
pnpm start
```

## Docker

```bash
cd docker
docker-compose up -d
```

The container runs stateless — no database, no volumes needed.

## CI/CD Integration

Protocol Guard can run security scans headlessly from CI/CD pipelines (GitHub Actions, GitLab CI, etc.) using the included CLI scanner. This is ideal for continuously scanning your MCP servers or A2A agents as part of your deployment pipeline.

### CLI Scanner

The `scan.mjs` script calls your Protocol Guard instance's API routes from the command line:

```bash
# Scan an MCP server
node scan.mjs --type mcp --url https://your-mcp-server.com/mcp

# Scan an A2A agent
node scan.mjs --type a2a --url https://your-a2a-agent.com/

# With authentication
node scan.mjs --type mcp --url https://server.com/mcp --auth bearer --token YOUR_TOKEN

# Fail the pipeline if any high or critical findings exist
node scan.mjs --type mcp --url https://server.com/mcp --fail-on high

# Output raw JSON for programmatic consumption
node scan.mjs --type mcp --url https://server.com/mcp --json
```

| Option | Description | Default |
|--------|-------------|---------|
| `--type` | Scan type: `mcp` or `a2a` | (required) |
| `--url` | Target server/agent URL | (required) |
| `--auth` | Auth type: `none`, `bearer`, `api_key`, `basic` | `none` |
| `--token` | Auth token/value | — |
| `--header` | Auth header name | `Authorization` |
| `--fail-on` | Fail if findings at this severity or above: `critical`, `high`, `medium`, `low`, `info` | — (never fail) |
| `--json` | Output raw JSON | `false` |
| `--base-url` | Protocol Guard instance URL | `http://localhost:3000` |

Exit codes: `0` = pass, `1` = findings above threshold, `2` = error.

### GitHub Actions

Add Protocol Guard to any GitHub Actions workflow:

- **Manual triggers** — run on demand from the GitHub UI with target URL and scan type
- **Scheduled scans** — add a cron schedule for nightly scans
- **Push/PR triggers** — run scans on every commit to catch regressions

**Quick start — add to any workflow:**

```yaml
- name: Start Protocol Guard
  run: |
    docker run -d -p 3000:3000 --name protocol-guard ghcr.io/arananet/protocol-guard:latest
    sleep 10

- name: Run MCP Security Scan
  run: |
    node scan.mjs \
      --type mcp \
      --url ${{ secrets.MCP_SERVER_URL }} \
      --base-url http://localhost:3000 \
      --fail-on high
```

### Docker in CI

You can run Protocol Guard as a Docker service container in any CI system:

```bash
# Build the image
docker build -f docker/Dockerfile -t protocol-guard .

# Run it
docker run -d -p 3000:3000 protocol-guard

# Scan your server
node scan.mjs --type mcp --url https://your-server.com/mcp --fail-on high

# Or use curl directly against the API
curl -X POST http://localhost:3000/api/mcp/security \
  -H "Content-Type: application/json" \
  -d '{"serverUrl": "https://your-server.com/mcp", "authType": "none"}'
```

## Project Structure

```
protocol-guard/
├── apps/
│   └── web/                          # Next.js application
│       └── src/app/
│           ├── page.tsx              # Landing page
│           ├── dashboard/
│           │   ├── page.tsx          # Main dashboard
│           │   ├── mcp/page.tsx      # MCP testing (compliance + interactive + security)
│           │   ├── a2a/page.tsx      # A2A testing (compliance + interactive + security)
│           │   └── ucp/page.tsx      # UCP testing
│           └── api/
│               ├── mcp/
│               │   ├── test/         # MCP compliance test
│               │   ├── tools/        # List MCP server tools
│               │   ├── call-tool/    # Call a specific MCP tool
│               │   └── security/     # OWASP MCP Top 10 scanner
│               ├── a2a/
│               │   ├── test/         # A2A compliance test
│               │   ├── agent-card/   # Fetch agent card (server-side proxy)
│               │   ├── send-task/    # Send task to A2A agent
│               │   └── security/     # A2A security scanner
│               └── ucp/
│                   └── test/         # UCP compliance test
├── packages/
│   ├── mcp-sdk/                      # MCP client library
│   ├── a2a-sdk/                      # A2A client library
│   ├── ucp-sdk/                      # UCP client library
│   └── shared/                       # Shared types
├── docker/                           # Docker configuration
├── .github/workflows/                # GitHub Actions (CI, release, security)
├── scan.mjs                          # CLI scanner for CI/CD pipelines
├── CHANGELOG.md                      # Version history
├── LICENSE                           # MIT License
└── SPEC.md                           # Project specification
```

## API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/api/mcp/test` | POST | Run MCP compliance test |
| `/api/mcp/tools` | POST | List available MCP server tools |
| `/api/mcp/call-tool` | POST | Call a specific tool with arguments |
| `/api/mcp/security` | POST | Run OWASP MCP Top 10 security scan |
| `/api/a2a/test` | POST | Run A2A compliance test |
| `/api/a2a/agent-card` | POST | Fetch agent card (server-side proxy) |
| `/api/a2a/send-task` | POST | Send a task to an A2A agent |
| `/api/a2a/security` | POST | Run A2A security scan |
| `/api/ucp/test` | POST | Run UCP compliance test |

## References & Credits

Protocol Guard's security scanners are built on the shoulders of these projects and standards. We credit them here because transparency matters — you should know where the ideas come from.

| Reference | Description |
|-----------|-------------|
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | The vulnerability taxonomy used by the MCP security scanner. Each finding maps to an OWASP category (MCP01–MCP10). |
| [MCP Server Security Standard (MSSS) v0.1](https://github.com/mcp-security-standard/mcp-server-security-standard) | 24 security controls across 8 domains (Filesystem, Execution, Network, Authorization, Input Validation, Logging, Supply Chain, Deployment). Protocol Guard implements the remotely-detectable subset (MCP-INPUT-01/02, MCP-NET-01, MCP-FS-01/02, MCP-EXEC-03) and cross-references every applicable finding with its control ID and compliance level (L1–L4). |
| [mcp-shield](https://github.com/riseandignite/mcp-shield) | Inspired the detection patterns for tool poisoning, hidden instructions, data exfiltration, and command injection analysis. |
| [a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner) | Inspired the A2A security scan approach: agent card validation, authentication posture, endpoint probing, and header analysis. |
| [MCP Specification](https://modelcontextprotocol.io/) | The official Model Context Protocol specification used for compliance testing. |
| [A2A Protocol](https://a2a-protocol.org/) | The Agent-to-Agent protocol specification used for compliance testing. |
| [UCP Specification](https://ucp.dev/latest/specification/overview) | The Universal Commerce Protocol specification used for business profile compliance testing. |

## Spec-Driven Development

This project uses [Spec Kit](https://github.com/github/spec-kit) for spec-driven development. All features follow a structured workflow: constitution, specification, planning, task breakdown, and implementation. Project principles live in `.specify/memory/constitution.md` and guide every technical decision.

## License

MIT — see [LICENSE](LICENSE).

Built with transparency in mind by Eduardo Arana & Soda 🥤

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/H2H51MPWG)
