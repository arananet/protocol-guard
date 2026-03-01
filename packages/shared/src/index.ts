import { z } from 'zod';

// Common API Response Types
export const ApiErrorSchema = z.object({
  code: z.string(),
  message: z.string(),
  details: z.unknown().optional(),
});

export type ApiError = z.infer<typeof ApiErrorSchema>;

export const PaginatedResponseSchema = <T extends z.ZodTypeAny>(itemSchema: T) =>
  z.object({
    data: z.array(itemSchema),
    pagination: z.object({
      page: z.number(),
      limit: z.number(),
      total: z.number(),
      hasMore: z.boolean(),
    }),
  });

// User Types
export const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string().optional(),
  createdAt: z.string().datetime(),
  role: z.enum(['admin', 'user']),
});

export type User = z.infer<typeof UserSchema>;

// API Key Types
export const APIKeySchema = z.object({
  id: z.string(),
  name: z.string(),
  key: z.string().optional(), // Only returned on creation
  prefix: z.string(),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime().optional(),
  lastUsedAt: z.string().datetime().optional(),
});

export type APIKey = z.infer<typeof APIKeySchema>;

// Test Result Types
export const TestResultSchema = z.object({
  id: z.string(),
  type: z.enum(['mcp', 'a2a']),
  targetId: z.string(),
  targetName: z.string(),
  status: z.enum(['passed', 'failed', 'warning', 'running']),
  passedCount: z.number(),
  failedCount: z.number(),
  warningCount: z.number(),
  results: z.array(z.object({
    ruleId: z.string(),
    name: z.string(),
    passed: z.boolean(),
    message: z.string(),
    severity: z.enum(['critical', 'warning', 'info']),
  })),
  createdAt: z.string().datetime(),
});

export type TestResult = z.infer<typeof TestResultSchema>;

// Re-export zod for convenience
export { z };
