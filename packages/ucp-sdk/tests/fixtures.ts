import type { UCPRawProfile } from '../src/types.js';

// Fixture based on the normative business profile example of the official
// UCP 2026-08-25 overview (ucp.dev/2026-08-25/specification/overview/).
export const currentProfile: UCPRawProfile = {
  ucp: {
    version: '2026-08-25',
    supported_versions: {
      '2026-01-23': 'https://business.example.com/ucp/2026-01-23',
    },
    services: {
      'dev.ucp.shopping': [
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/overview/',
          transport: 'rest',
          endpoint: 'https://business.example.com/ucp/v1',
          schema: 'https://ucp.dev/2026-08-25/services/shopping/rest.openapi.json',
        },
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/overview/',
          transport: 'mcp',
          endpoint: 'https://business.example.com/ucp/mcp',
          schema: 'https://ucp.dev/2026-08-25/services/shopping/mcp.openrpc.json',
        },
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/overview/',
          transport: 'a2a',
          endpoint: 'https://business.example.com/.well-known/agent-card.json',
        },
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/overview/',
          transport: 'embedded',
          schema: 'https://ucp.dev/2026-08-25/services/shopping/embedded.openrpc.json',
        },
      ],
    },
    capabilities: {
      'dev.ucp.shopping.checkout': [
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/shopping/checkout',
          schema: 'https://ucp.dev/2026-08-25/schemas/shopping/checkout.json',
        },
      ],
      'dev.ucp.shopping.cart': [
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/shopping/cart',
          schema: 'https://ucp.dev/2026-08-25/schemas/shopping/cart.json',
        },
      ],
      'dev.ucp.shopping.catalog.search': [
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/shopping/catalog',
          schema: 'https://ucp.dev/2026-08-25/schemas/shopping/catalog_search.json',
        },
      ],
      'dev.ucp.shopping.fulfillment': [
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/shopping/extensions/fulfillment',
          schema: 'https://ucp.dev/2026-08-25/schemas/shopping/fulfillment.json',
          extends: 'dev.ucp.shopping.checkout',
        },
      ],
      'dev.ucp.common.identity_linking': [
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/common/identity-linking/',
          schema: 'https://ucp.dev/2026-08-25/schemas/common/identity_linking.json',
          config: {
            providers: {
              'com.example.idp': [{ type: 'oauth2', auth_url: 'https://accounts.example.com/' }],
            },
            scopes: { 'dev.ucp.shopping.order:read': {} },
          },
        },
      ],
      // Payment capability whose spec and schema live on different hosts
      // on purpose: differing hosts are valid in 2026-08-25.
      'dev.ucp.common.payment.ap2_mandate': [
        {
          version: '2026-08-25',
          spec: 'https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates',
          schema: 'https://schemas.example.net/ucp/payment_ap2_mandate.json',
          extends: ['dev.ucp.shopping.checkout', 'dev.ucp.shopping.cart'],
        },
      ],
    },
    payment_handlers: {
      'com.example.processor_tokenizer': [
        {
          id: 'processor_tokenizer',
          version: '2026-08-25',
          spec: 'https://example.com/specs/payments/processor_tokenizer',
          schema: 'https://example.com/specs/payments/merchant_tokenizer.json',
          available_instruments: [{ type: 'card' }],
        },
      ],
    },
  },
  keys: [
    {
      kid: 'business_2025',
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      use: 'sig',
      x: 'qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA',
      y: 'Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0',
    },
  ],
};

export const legacyProfile: UCPRawProfile = {
  ucp: {
    version: '2026-01-23',
    services: {
      'dev.ucp.shopping': {
        version: '2026-01-23',
        spec: 'https://ucp.dev/2026-01-23/specification/overview/',
        transport: {
          rest: {
            schema: 'https://ucp.dev/2026-01-23/services/shopping/rest.openapi.json',
            endpoint: 'https://legacy.example.com/ucp/v1',
          },
          mcp: {
            schema: 'https://ucp.dev/2026-01-23/services/shopping/mcp.openrpc.json',
            endpoint: 'https://legacy.example.com/ucp/mcp',
          },
        },
      },
    },
    capabilities: {
      'dev.ucp.shopping.checkout': {
        version: '2026-01-23',
        spec: 'https://ucp.dev/2026-01-23/specification/shopping/checkout',
        schema: 'https://ucp.dev/2026-01-23/schemas/shopping/checkout.json',
      },
    },
    payment_handlers: {
      'com.google.pay': {
        version: '2026-01-23',
        spec: 'https://example.com/gpay',
        schema: 'https://example.com/gpay.json',
      },
    },
  },
  signing_keys: [
    { kid: 'legacy-1', kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' },
  ],
};

