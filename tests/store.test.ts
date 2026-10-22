import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MemoryEventStore, boundLimit, getStore, __resetStore } from "@/lib/store";
import { SCHEMA_SQL } from "@/lib/store/postgres";
import type { AlertEvent } from "@/lib/types";
import { CUSTOMER, FAKE } from "./fixtures";

/**
 * These are contract tests. They run against MemoryEventStore because that is
 * what can execute without infrastructure, but they describe what ANY store
 * must do - including the Postgres implementation, which has not yet been run
 * against a live database. If Postgres is wired up, point these at it.
 */

function event(partial: Partial<AlertEvent> = {}): AlertEvent {
  return {
    id: crypto.randomUUID(),
    at: new Date().toISOString(),
    action: "redact",
    categories: ["secret"],
    counts: { secret: 1 },
    hash: "0123456789abcdef",
    classifierFailed: false,
    ...partial,
  };
}

describe("store selection", () => {
  afterEach(() => __resetStore());

  it("uses the in-memory store when DATABASE_URL is unset", () => {
    delete process.env.DATABASE_URL;
    __resetStore();
    const store = getStore();
    expect(store.name).toBe("memory");
    expect(store.durable).toBe(false);
  });

  it("never reports the in-memory store as durable", () => {
    expect(new MemoryEventStore().durable).toBe(false);
  });

  it("selects Postgres when DATABASE_URL is set", () => {
    process.env.DATABASE_URL = "postgres://user:pw@localhost:5432/db";
    __resetStore();
    const store = getStore();
    expect(store.name).toBe("postgres");
    expect(store.durable).toBe(true);
    delete process.env.DATABASE_URL;
    __resetStore();
  });
});

describe("append and read back", () => {
  let store: MemoryEventStore;
  beforeEach(() => {
    store = new MemoryEventStore();
  });

  it("returns an appended event", async () => {
    const e = event();
    await store.append(e);
    const page = await store.list(10);
    expect(page.events).toHaveLength(1);
    expect(page.events[0].id).toBe(e.id);
  });

  it("returns newest first", async () => {
    await store.append(event({ at: "2026-10-22T10:00:00.000Z", hash: "aaaaaaaaaaaaaaaa" }));
    await store.append(event({ at: "2026-10-22T11:00:00.000Z", hash: "bbbbbbbbbbbbbbbb" }));
    const page = await store.list(10);
    expect(page.events[0].hash).toBe("bbbbbbbbbbbbbbbb");
  });

  it("reports a total independent of page size", async () => {
    for (let i = 0; i < 12; i++) await store.append(event());
    const page = await store.list(5);
    expect(page.events).toHaveLength(5);
    expect(page.total).toBe(12);
  });
});

describe("pagination is bounded", () => {
  it("clamps absurd, missing and hostile page sizes", () => {
    expect(boundLimit(10)).toBe(10);
    expect(boundLimit(0)).toBe(1);
    expect(boundLimit(-5)).toBe(1);
    expect(boundLimit(100_000)).toBe(200);
    expect(boundLimit("abc")).toBe(50);
    expect(boundLimit(null)).toBe(50);
    expect(boundLimit(undefined)).toBe(50);
    expect(boundLimit(7.9)).toBe(7);
  });

  it("walks pages with the cursor without repeating or skipping", async () => {
    const store = new MemoryEventStore();
    for (let i = 0; i < 10; i++) {
      await store.append(
        event({ at: new Date(Date.UTC(2026, 9, 22, 10, i)).toISOString() })
      );
    }

    const seen: string[] = [];
    let cursor: string | undefined;
    for (let guard = 0; guard < 10; guard++) {
      const page = await store.list(3, cursor);
      seen.push(...page.events.map((e) => e.id));
      if (!page.nextBefore) break;
      cursor = page.nextBefore;
    }

    expect(seen).toHaveLength(10);
    expect(new Set(seen).size).toBe(10); // nothing repeated
  });

  it("ends with a null cursor", async () => {
    const store = new MemoryEventStore();
    await store.append(event());
    expect((await store.list(50)).nextBefore).toBeNull();
  });
});

describe("the store is append-only by construction", () => {
  it("exposes no update or delete method", () => {
    const store = new MemoryEventStore() as unknown as Record<string, unknown>;
    for (const forbidden of ["update", "delete", "remove", "edit", "clear", "truncate"]) {
      expect(store[forbidden], forbidden).toBeUndefined();
    }
  });

  it("keeps earlier events when later ones arrive", async () => {
    const store = new MemoryEventStore();
    const first = event();
    await store.append(first);
    for (let i = 0; i < 5; i++) await store.append(event());
    const page = await store.list(50);
    expect(page.events.map((e) => e.id)).toContain(first.id);
  });
});

/** Column names declared inside CREATE TABLE, ignoring types and constraints. */
function schemaColumns(): string[] {
  const table = SCHEMA_SQL.match(/CREATE TABLE[^(]*\(([\s\S]*?)\n\);/);
  if (!table) throw new Error("could not find the CREATE TABLE body");
  return table[1]
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("--"))
    .map((line) => line.split(/\s+/)[0].toLowerCase())
    .filter((name) => /^[a-z_]+$/.test(name));
}

describe("the schema holds no content columns", () => {
  it("defines exactly the metadata columns, and no others", () => {
    expect(schemaColumns().sort()).toEqual([
      "action",
      "at",
      "categories",
      "classifier_failed",
      "counts",
      "created_at",
      "hash",
      "id",
    ]);
  });

  it("has no column whose name suggests it could hold content", () => {
    // Checks column NAMES, not the SQL text - "TEXT" is a column type and
    // appears legitimately.
    const names = schemaColumns();
    for (const forbidden of ["prompt", "content", "body", "snippet", "value", "reason", "span"]) {
      expect(names, forbidden).not.toContain(forbidden);
    }
  });

  it("indexes the columns the admin view reads by", () => {
    expect(SCHEMA_SQL).toContain("audit_events_at_id_desc");
    expect(SCHEMA_SQL).toContain("audit_events_action");
  });
});

describe("stored events carry no sensitive values", () => {
  it("a round trip preserves metadata and nothing else", async () => {
    const store = new MemoryEventStore();
    await store.append(event());
    const serialized = JSON.stringify((await store.list(10)).events);
    for (const value of [CUSTOMER.emailA, CUSTOMER.nameA, FAKE.stripeKey, FAKE.dbPassword]) {
      expect(serialized).not.toContain(value);
    }
  });
});
