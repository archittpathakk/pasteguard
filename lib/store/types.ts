import type { AlertEvent } from "../types";

/**
 * The audit store.
 *
 * Note what this interface does NOT have: no update, no delete, no edit.
 * Append-only is enforced by the shape of the contract, not by convention -
 * there is no method an ordinary caller could use to rewrite history. The
 * database role should be granted INSERT and SELECT only, so the guarantee
 * holds at the permission level too.
 */
export interface EventStore {
  /** Human-readable, shown in diagnostics. Never includes credentials. */
  readonly name: string;
  /**
   * Whether events survive a restart. The API returns this to the UI so the
   * interface can say "demo storage" instead of implying an audit trail.
   */
  readonly durable: boolean;

  /** Prepare the store. Safe to call repeatedly. */
  init(): Promise<void>;

  /** Add one event. Throws if it could not be stored - never silently drops. */
  append(event: AlertEvent): Promise<void>;

  /** Newest first, bounded. `before` is an ISO timestamp cursor. */
  list(limit: number, before?: string): Promise<EventPage>;
}

export interface EventPage {
  events: AlertEvent[];
  /** Total rows known to the store, for the UI to show a count. */
  total: number;
  /** Cursor for the next page, or null when there is no more. */
  nextBefore: string | null;
}

export const MAX_PAGE = 200;
export const DEFAULT_PAGE = 50;

/**
 * Clamp a caller-supplied page size into the allowed range.
 *
 * Absent means "use the default", not "use the minimum". Number(null) is 0
 * and Number("") is 0, both finite, so they must be rejected before the
 * numeric check - otherwise a missing ?limit= returns a single row.
 */
export function boundLimit(raw: unknown): number {
  if (raw === null || raw === undefined) return DEFAULT_PAGE;
  if (typeof raw === "string" && raw.trim() === "") return DEFAULT_PAGE;
  const n = Number(raw);
  if (!Number.isFinite(n)) return DEFAULT_PAGE;
  return Math.min(Math.max(Math.floor(n), 1), MAX_PAGE);
}
