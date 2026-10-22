import { getStore } from "./store";

/**
 * Operational status.
 *
 * Reports whether things are CONFIGURED, never what they are configured to.
 * No key values, no connection strings, no stack traces - a health endpoint
 * that leaks those is a gift to an attacker.
 *
 * Pure so it can be tested; the route is a thin wrapper that first opts out
 * of prerendering.
 */

export interface Health {
  ok: boolean;
  status: "operational" | "degraded";
  classifier: { provider: string; keyVariable: string; configured: boolean };
  auditStore: { name: string; durable: boolean };
  adminView: { configured: boolean };
  hint?: string;
}

function present(name: string): boolean {
  const v = process.env[name];
  return typeof v === "string" && v.trim().length > 0;
}

export function buildHealth(): Health {
  const provider = (process.env.AI_PROVIDER ?? "gemini").toLowerCase().trim();
  const usesAnthropic = provider === "anthropic" || provider === "claude";
  const keyVariable = usesAnthropic ? "ANTHROPIC_API_KEY" : "GEMINI_API_KEY";

  const configured = usesAnthropic
    ? present("ANTHROPIC_API_KEY")
    : present("GEMINI_API_KEY") || present("GOOGLE_API_KEY");

  const store = getStore();

  // An instance that cannot classify is degraded, not healthy. Reporting
  // "ok" while the core function is unavailable is the kind of green light
  // that hides an outage.
  return {
    ok: configured,
    status: configured ? "operational" : "degraded",
    classifier: { provider, keyVariable, configured },
    auditStore: { name: store.name, durable: store.durable },
    adminView: { configured: present("ADMIN_PASSWORD") },
    hint: configured
      ? undefined
      : `${keyVariable} is not visible to the server. Set it for this environment and deploy again - environment variables only reach a build created after they were added.`,
  };
}
