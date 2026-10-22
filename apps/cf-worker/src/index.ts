import { Container, getContainer } from "@cloudflare/containers";

/**
 * Cloudflare Containers wrapper for protocol-guard.
 * The application itself is the existing Next.js standalone server
 * (docker/Dockerfile); this Worker only routes traffic to it.
 * See .openspec/specs/cloudflare-migration.md.
 */
export class ProtocolGuardContainer extends Container {
  defaultPort = 3000;
  sleepAfter = "10m";
  envVars = {
    NODE_ENV: "production",
    PORT: "3000",
    HOSTNAME: "0.0.0.0",
  };
}

interface Env {
  PROTOCOL_GUARD: DurableObjectNamespace<ProtocolGuardContainer>;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Singleton instance: protocol-guard is stateless, one warm
    // container serves all traffic until it scales out.
    const container = getContainer(env.PROTOCOL_GUARD);
    return container.fetch(request);
  },
};
