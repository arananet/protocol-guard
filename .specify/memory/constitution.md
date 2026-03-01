# Protocol Guard Constitution

## Core Principles

### I. Privacy-First, Zero-Persistence

Protocol Guard MUST NEVER store user data, URLs, credentials, tokens, or scan results. All operations are stateless and ephemeral. No database, no local storage, no cookies for user data. Scan results exist only in the browser session and are discarded on navigation. This principle is non-negotiable and applies to every feature, API route, and SDK.

### II. Transparency and Open Source Integrity

All scanning logic MUST be real, auditable code. No placeholders, no stubs, no fake results. Every vulnerability check must perform actual pattern matching, real HTTP requests, or genuine protocol handshakes. Security tools must never be black boxes. The source code is the documentation.

### III. Protocol Specification Fidelity

Every compliance check and security scan MUST trace back to an official specification or established standard:
- MCP compliance rules map to the Model Context Protocol specification
- A2A compliance rules map to the Agent-to-Agent protocol specification
- UCP compliance rules map to the published UCP specification at ucp.dev
- Security scans map to OWASP MCP Top 10 or equivalent recognized frameworks

Do not invent rules. Do not add checks without a traceable source.

### IV. Test-First Development (NON-NEGOTIABLE)

All new features MUST follow test-driven development:
1. Write tests that define the expected behavior
2. Verify tests fail (Red phase)
3. Implement the minimum code to pass (Green phase)
4. Refactor while keeping tests green (Refactor phase)

Every SDK package must have a corresponding test suite. API routes must be testable in isolation. The CI pipeline must pass lint, test, and build gates before any deployment.

### V. Monorepo Modularity

The project follows a strict monorepo architecture with clear separation:
- `packages/mcp-sdk` -- MCP protocol types, client, and compliance logic
- `packages/a2a-sdk` -- A2A protocol types, client, and compliance logic
- `packages/ucp-sdk` -- UCP protocol types, client, and compliance logic
- `packages/shared` -- Cross-protocol utilities only
- `apps/web` -- Next.js frontend and API routes

SDK packages MUST be independently publishable. Shared code goes in `packages/shared` only when it serves multiple protocols. No circular dependencies between packages.

### VI. Simplicity and YAGNI

Start with the simplest solution that works. Do not add features speculatively. Do not over-abstract or over-engineer. Specific guidelines:
- No wrapper libraries around framework features
- No premature optimization
- Maximum 3 layers of abstraction for any feature path
- If a feature is not traced to a user story or protocol spec, it does not belong

### VII. Security by Default

As a security scanning platform, Protocol Guard must lead by example:
- All HTTP requests include appropriate timeouts and error handling
- No secrets or credentials in source code
- CORS and security headers on all API responses
- Input validation on all user-provided URLs and parameters
- Dependency auditing in CI (pnpm audit, TruffleHog, CodeQL)

### VIII. Consistent User Experience

- Dark/light theme support across all pages
- Consistent color scheme using HSL CSS variables
- Findings displayed with severity levels (Critical, High, Medium, Low, Info)
- Real-time scan progress feedback
- Responsive layout for all screen sizes

## Technology Constraints

### Stack Requirements

| Layer | Technology | Version |
|-------|-----------|---------|
| Runtime | Node.js | >= 20.0.0 |
| Package Manager | pnpm | 9.x |
| Framework | Next.js | 14.x (App Router) |
| Language | TypeScript | 5.x (strict mode) |
| Styling | Tailwind CSS | 3.x |
| Build | Turborepo | 2.x |
| Testing | Vitest | 2.x |
| Linting | ESLint | 9.x (flat config) |
| Container | Docker | Multi-stage, node:20-alpine |
| Deployment | Railway | With CI-gated deploys |

### Architecture Rules

- Next.js `output: 'standalone'` for container deployment
- API routes handle protocol communication server-side (browser CORS bypass)
- SDK packages export TypeScript types alongside runtime code
- No client-side secret exposure
- All protocol clients use `AbortSignal` timeouts

## Development Workflow

### Branch Strategy

- `main` is the production branch
- Feature branches for new protocol support or major changes
- All changes go through CI (lint, test, build) before merge
- Deployments are gated: CI must pass before Railway webhook fires

### Code Review Standards

- Every PR must pass the CI pipeline (lint, test, build)
- Scanner logic changes require verification that checks are real (no stubs)
- Protocol compliance changes must reference the relevant specification section
- No `any` types without documented justification

### Quality Gates

- [ ] ESLint passes with zero errors and zero warnings
- [ ] All Vitest tests pass with coverage
- [ ] Turborepo build completes for all packages and apps
- [ ] No new `[NEEDS CLARIFICATION]` markers remain in specs
- [ ] Docker build succeeds

## Governance

This constitution is the supreme governing document for Protocol Guard development. All technical decisions, feature additions, and architecture changes MUST comply with the principles defined here.

### Amendment Process

Modifications to this constitution require:
1. Explicit documentation of the rationale for change
2. Review and approval by project maintainers (Eduardo Arana)
3. Backwards compatibility assessment
4. Update of the version and amendment date below

### Enforcement

- All PRs and code reviews must verify constitutional compliance
- Complexity additions must be justified against Principle VI (Simplicity)
- Privacy violations (Principle I) are grounds for immediate revert
- Scanner authenticity violations (Principle II) are grounds for immediate revert

**Version**: 1.0.0 | **Ratified**: 2025-03-01 | **Last Amended**: 2025-03-01
