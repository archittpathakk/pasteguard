import type { AlertEvent } from "../types";
import { boundLimit, type EventPage, type EventStore } from "./types";

/**
 * Fallback store, used when no DATABASE_URL is configured.
 *
 * It is NOT durable and does not pretend to be: `durable` is false, the API
 * passes that to the UI, and the UI says so on screen. On serverless this is
 * also per-instance, so two requests may see different data. It exists so the
 * product runs with zero infrastructure, not as a production store.
 */
export class MemoryEventStore implements EventStore {
  readonly name = "memory";
  readonly durable = false;

  private events: AlertEvent[] = [];
  private readonly cap: number;

  constructor(cap = 500) {
    this.cap = cap;
  }

  async init(): Promise<void> {
    /* nothing to prepare */
  }

  async append(event: AlertEvent): Promise<void> {
    this.events.unshift(event);
    if (this.events.length > this.cap) this.events.length = this.cap;
  }

  async list(limit: number, before?: string): Promise<EventPage> {
    const size = boundLimit(limit);
    const filtered = before
      ? this.events.filter((e) => e.at < before)
      : this.events;
    const page = filtered.slice(0, size);
    return {
      events: page,
      total: this.events.length,
      nextBefore: filtered.length > size ? page[page.length - 1].at : null,
    };
  }
}
