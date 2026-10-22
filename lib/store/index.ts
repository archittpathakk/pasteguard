import { MemoryEventStore } from "./memory";
import { PostgresEventStore } from "./postgres";
import type { EventStore } from "./types";

// One store per process. Which one depends only on configuration:
//
//   DATABASE_URL set    -> Postgres, durable
//   DATABASE_URL unset  -> in-memory, NOT durable, and the UI says so
//
// There is deliberately no third mode where memory is presented as durable.

let instance: EventStore | null = null;

export function getStore(): EventStore {
  if (instance) return instance;

  const url = process.env.DATABASE_URL?.trim();
  instance = url ? new PostgresEventStore(url) : new MemoryEventStore();
  return instance;
}

/** Test-only: drop the cached store so a test can choose its own. */
export function __resetStore(next: EventStore | null = null) {
  instance = next;
}

export type { EventStore, EventPage } from "./types";
export { boundLimit, DEFAULT_PAGE, MAX_PAGE } from "./types";
export { MemoryEventStore } from "./memory";
export { PostgresEventStore, SCHEMA_SQL } from "./postgres";
