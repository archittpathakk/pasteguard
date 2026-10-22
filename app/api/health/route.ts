import { connection } from "next/server";
import { buildHealth } from "@/lib/health";

// Operational status. The logic lives in lib/health.ts so it can be tested;
// this route only opts out of prerendering and serializes the result.

export async function GET() {
  // Without this the route is evaluated at BUILD time and reports the
  // configuration as it was then - a health endpoint that lies after a
  // redeploy is worse than none.
  await connection();

  const health = buildHealth();
  return Response.json(health, {
    status: health.ok ? 200 : 503,
    headers: { "cache-control": "no-store" },
  });
}
