# Audit event storage

PasteGuard stores one metadata record per checked paste. It stores **no prompt
text, no detected values and no model output**. The whole schema is eight
columns and there is nowhere for content to hide.

## Two stores, chosen by configuration

| `DATABASE_URL` | Store | Durable | Used for |
|---|---|---|---|
| unset | in-memory | **No** | Local development and demos with no infrastructure |
| set | PostgreSQL | Yes | Anything where the log needs to survive a restart |

There is deliberately no third mode in which memory is presented as durable.
The API returns a `durable` flag with every read and the admin view prints
*"Demo storage: these events are held in memory and are lost when the server
restarts"* when it is false.

On serverless the in-memory store is also **per-instance**: two requests can
land on different instances and see different data. Treat it as a demo
convenience only.

## ⚠ Status of the PostgreSQL implementation

`lib/store/postgres.ts` is **written but has not been executed against a live
database.** No `DATABASE_URL` was available during development. It typechecks,
its SQL is written against documented PostgreSQL behaviour, and the contract
tests in `tests/store.test.ts` describe what it must do — but nobody has run
it. Verify it with the checklist below before relying on it.

## Setting it up

Any PostgreSQL will do. Neon, Supabase and Vercel Postgres all work and have
free tiers.

1. Create a database and copy its connection string.
2. Add it to the environment:

   ```
   DATABASE_URL=postgres://user:password@host:5432/dbname?sslmode=require
   ```

   Locally that goes in `.env.local`. On Vercel it goes in Settings →
   Environment Variables with **Production** ticked, followed by a redeploy —
   environment variables only reach a build created after they were added.

3. Restart (or redeploy). The schema is created automatically on first use;
   `CREATE TABLE IF NOT EXISTS` makes that safe to repeat.

## Making append-only real

The application cannot rewrite history: `EventStore` exposes no update or
delete method, and no route calls one. That is a guarantee of this codebase,
not of the database.

To make it a guarantee of the database as well, give the application role
`INSERT` and `SELECT` only:

```sql
CREATE ROLE pasteguard_app LOGIN PASSWORD 'choose-a-strong-one';
GRANT CONNECT ON DATABASE your_db TO pasteguard_app;
GRANT USAGE ON SCHEMA public TO pasteguard_app;
GRANT INSERT, SELECT ON audit_events TO pasteguard_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM pasteguard_app;
```

Run the schema as a migration user, then point `DATABASE_URL` at
`pasteguard_app`. A stolen application credential then cannot erase the
record of what it did.

## Verification checklist

Run these after configuring a database. Do not record the Postgres path as
working until each one has actually been observed.

- [ ] App starts with `DATABASE_URL` set and no error in the log
- [ ] `audit_events` exists, with the indexes `audit_events_at_id_desc` and `audit_events_action`
- [ ] Checking a paste inserts exactly one row
- [ ] The admin view lists that event after signing in
- [ ] Restart the server — the event is **still there** (this is the whole point)
- [ ] The admin view reports `durable: true`
- [ ] Insert 60+ events, confirm paging with `?limit=` and `?before=` neither repeats nor skips
- [ ] `SELECT * FROM audit_events` shows no prompt text, no email addresses, no secrets
- [ ] With the restricted role, `UPDATE audit_events SET action='allow'` is refused
- [ ] Stop the database and check a paste: the UI reports the event was **not** recorded, rather than claiming success

That last one matters most. A write failure returns HTTP 503 and `stored:
false`. Telling someone their override was logged when it was not would make
the audit trail quietly incomplete, which is worse than visibly broken.

## Schema

```sql
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
```

`hash` is a truncated SHA-256 of the original input, used to correlate an
override with the decision it overrode. **It is not anonymisation.** A hash of
a short, low-entropy input can be recovered by guessing, and truncation raises
collision risk. Treat it as pseudonymous, and do not publish it.

## Retention

Not implemented. Decide a retention period before real use and enforce it with
a scheduled job, for example:

```sql
DELETE FROM audit_events WHERE at < now() - INTERVAL '90 days';
```

Run that as a maintenance role, not as the application role — the application
must not hold `DELETE`.
