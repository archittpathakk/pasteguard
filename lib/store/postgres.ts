import { Pool } from "pg";
import type { AlertEvent, Action, Category } from "../types";
import { boundLimit, type EventPage, type EventStore } from "./types";

/**
 * Durable audit store.
 *
 * ⚠ NOT YET EXECUTED AGAINST A LIVE DATABASE. No DATABASE_URL was available
 * during development, so this code typechecks and its SQL is written against
 * the documented Postgres behaviour, but it has not been run. See
 * docs/DATABASE.md for the exact steps to verify it before relying on it.
 *
 * Design notes:
 *  - Append-only: this class exposes no update or delete. Grant the
 *    application role INSERT and SELECT only, so the guarantee is enforced
 *    by the database and not merely by this file.
 *  - Keyset pagination on (at, id), not OFFSET, so paging stays correct
 *    while new rows arrive and stays fast as the table grows.
 *  - No prompt text, no finding text, no detected values. The columns below
 *    are the whole schema; there is nowhere for content to hide.
 */

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS audit_events (
  id                UUID PRIMARY KEY,
  at                TIMESTAMPTZ  NOT NULL,
  action            TEXT         NOT NULL,
  categories        TEXT[]       NOT NULL DEFAULT '{}',
  counts            JSONB        NOT NULL DEFAULT '{}'::jsonb,
  hash              TEXT         NOT NULL DEFAULT '',
  classifier_failed BOOLEAN      NOT NULL DEFAULT FALSE,
  created_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Newest-first reads with a keyset cursor.
CREATE INDEX IF NOT EXISTS audit_events_at_id_desc
  ON audit_events (at DESC, id DESC);

-- Override rate per category is the headline admin metric.
CREATE INDEX IF NOT EXISTS audit_events_action
  ON audit_events (action);
`;

interface Row {
  id: string;
  at: Date;
  action: string;
  categories: string[] | null;
  counts: Record<string, number> | null;
  hash: string | null;
  classifier_failed: boolean;
}

function toEvent(r: Row): AlertEvent {
  return {
    id: r.id,
    at: r.at.toISOString(),
    action: r.action as Action,
    categories: (r.categories ?? []) as Category[],
    counts: r.counts ?? {},
    hash: r.hash ?? "",
    classifierFailed: r.classifier_failed,
  };
}

export class PostgresEventStore implements EventStore {
  readonly name = "postgres";
  readonly durable = true;

  private pool: Pool;
  private ready: Promise<void> | null = null;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: 3, // serverless: many short-lived instances, keep each pool small
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 5_000,
      // Hosted Postgres (Neon, Supabase, Vercel) terminates TLS with a
      // certificate the default trust store does not always carry.
      ssl: connectionString.includes("sslmode=disable")
        ? undefined
        : { rejectUnauthorized: false },
    });
  }

  /** Runs the schema once per process. Safe to call on every request. */
  init(): Promise<void> {
    this.ready ??= this.pool.query(SCHEMA_SQL).then(() => undefined);
    return this.ready;
  }

  async append(event: AlertEvent): Promise<void> {
    await this.init();
    await this.pool.query(
      `INSERT INTO audit_events
         (id, at, action, categories, counts, hash, classifier_failed)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (id) DO NOTHING`,
      [
        event.id,
        event.at,
        event.action,
        event.categories,
        JSON.stringify(event.counts),
        event.hash,
        event.classifierFailed,
      ]
    );
  }

  async list(limit: number, before?: string): Promise<EventPage> {
    await this.init();
    const size = boundLimit(limit);

    // Ask for one extra row to learn whether a next page exists.
    const rows = before
      ? await this.pool.query<Row>(
          `SELECT * FROM audit_events WHERE at < $1 ORDER BY at DESC, id DESC LIMIT $2`,
          [before, size + 1]
        )
      : await this.pool.query<Row>(
          `SELECT * FROM audit_events ORDER BY at DESC, id DESC LIMIT $1`,
          [size + 1]
        );

    const hasMore = rows.rows.length > size;
    const page = rows.rows.slice(0, size).map(toEvent);

    const totalResult = await this.pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM audit_events`
    );

    return {
      events: page,
      total: Number(totalResult.rows[0]?.count ?? page.length),
      nextBefore: hasMore && page.length > 0 ? page[page.length - 1].at : null,
    };
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
