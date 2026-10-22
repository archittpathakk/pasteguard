// Fixed-window rate limiting, in process memory.
//
// HONEST LIMITATION: on serverless each instance keeps its own counter, so the
// effective limit is per-instance, not global. That makes this a brake on
// casual abuse, not a guarantee. A real quota needs shared state (Redis, or
// the database). This is documented in README and SECURITY rather than being
// quietly presented as a global limit.

interface Window {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Window>();
const MAX_KEYS = 5000; // bound the map so a flood of IPs cannot grow it forever

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfterSeconds: number;
}

export function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
  now = Date.now()
): RateLimitResult {
  const existing = buckets.get(key);

  if (!existing || existing.resetAt <= now) {
    if (buckets.size >= MAX_KEYS) evictExpired(now);
    const fresh = { count: 1, resetAt: now + windowMs };
    buckets.set(key, fresh);
    return {
      allowed: true,
      remaining: limit - 1,
      resetAt: fresh.resetAt,
      retryAfterSeconds: 0,
    };
  }

  existing.count += 1;
  const allowed = existing.count <= limit;
  return {
    allowed,
    remaining: Math.max(0, limit - existing.count),
    resetAt: existing.resetAt,
    retryAfterSeconds: allowed ? 0 : Math.ceil((existing.resetAt - now) / 1000),
  };
}

function evictExpired(now: number) {
  for (const [k, v] of buckets) {
    if (v.resetAt <= now) buckets.delete(k);
  }
  // Still full of live windows: drop the oldest few rather than refuse service.
  if (buckets.size >= MAX_KEYS) {
    const oldest = [...buckets.entries()]
      .sort((a, b) => a[1].resetAt - b[1].resetAt)
      .slice(0, Math.ceil(MAX_KEYS / 10));
    for (const [k] of oldest) buckets.delete(k);
  }
}

/** Test-only: forget all windows. */
export function resetRateLimits() {
  buckets.clear();
}

/**
 * Best-effort client identity. Proxy headers are client-controlled, so this
 * is not an identity for authorization - only for coarse throttling.
 */
export function clientKey(req: Request): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.headers.get("x-real-ip") ?? "unknown";
}
