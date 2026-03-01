# ─── Build stage ──────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

# Install pnpm
RUN corepack enable && corepack prepare pnpm@9.0.0 --activate

WORKDIR /app

# Copy workspace config first (better layer caching)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./

# Copy all package.json files for dependency resolution
COPY apps/web/package.json apps/web/
COPY packages/mcp-sdk/package.json packages/mcp-sdk/
COPY packages/a2a-sdk/package.json packages/a2a-sdk/
COPY packages/ucp-sdk/package.json packages/ucp-sdk/
COPY packages/shared/package.json packages/shared/

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy all source code
COPY . .

# Generate Prisma client if schema exists (legacy leftover, app is stateless)
RUN if [ -f apps/web/prisma/schema.prisma ]; then \
      cd apps/web && npx prisma generate; \
    fi

# Build the entire monorepo (packages first via turbo dependency graph)
RUN pnpm build

# ─── Production stage ─────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

# Create non-root user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Next.js standalone output puts everything needed in .next/standalone
# It includes a minimal server.js at the monorepo root level
COPY --from=builder /app/apps/web/.next/standalone ./

# Static files must be copied separately (standalone output does not include these)
COPY --from=builder /app/apps/web/.next/static ./apps/web/.next/static

# Copy CLI scanner for CI/CD usage
COPY --from=builder /app/scan.mjs ./scan.mjs

# Set ownership
RUN chown -R nextjs:nodejs /app

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# The standalone server.js is at the monorepo root in the standalone output
CMD ["node", "apps/web/server.js"]
