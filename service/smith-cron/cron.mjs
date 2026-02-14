#!/usr/bin/env node
/**
 * smith-cron: Scheduler daemon that loads cron jobs from PostgreSQL,
 * maintains in-memory Cron instances (via croner), and fires
 * SessionStartRequest messages to NATS when schedules hit.
 *
 * No polling. Sleeps until the next fire time. Config changes arrive
 * via NATS subscription on smith.cron.reload.
 *
 * Env:
 *   NATS_URL       (default: nats://127.0.0.1:7222)
 *   SMITH_CRON_PG  (default: postgresql://smith_app:smith-app-dev@postgres:5432/smith)
 */

import { connect, StringCodec } from "nats";
import pg from "pg";
import { Cron } from "croner";

const NATS_URL = process.env.NATS_URL ?? "nats://127.0.0.1:7222";
const PG_URL =
  process.env.SMITH_CRON_PG ??
  "postgresql://smith_app:smith-app-dev@postgres:5432/smith";

const sc = StringCodec();
const pool = new pg.Pool({ connectionString: PG_URL, max: 3 });

/** @type {Cron[]} */
let activeCrons = [];

/** @type {import("nats").NatsConnection} */
let nc;

// ── Helpers ─────────────────────────────────────────────────────────

function log(...args) {
  console.log("[smith-cron]", ...args);
}

function stopAll() {
  for (const c of activeCrons) {
    c.stop();
  }
  activeCrons = [];
}

async function loadAndSchedule() {
  stopAll();

  let rows;
  try {
    const res = await pool.query(
      "SELECT * FROM cron_jobs WHERE enabled = true"
    );
    rows = res.rows;
  } catch (err) {
    log("failed to load cron jobs:", err.message);
    return;
  }

  log(`loaded ${rows.length} enabled cron job(s)`);

  for (const job of rows) {
    try {
      const cron = new Cron(job.schedule, async () => {
        await onFire(job, cron);
      });
      activeCrons.push(cron);
      log(`scheduled "${job.name}" [${job.id.slice(0, 8)}] — ${job.schedule}`);
    } catch (err) {
      log(`invalid schedule for "${job.name}": ${err.message}`);
    }
  }
}

async function onFire(job, cron) {
  const scheduledAt = new Date().toISOString();
  log(`FIRE "${job.name}" [${job.id.slice(0, 8)}] goal="${job.goal.slice(0, 60)}"`);

  // 1. Publish SessionStartRequest
  const payload = {
    goal: job.goal,
    metadata: {
      trigger: "cron",
      cron_job_id: job.id,
      cron_name: job.name,
      agent_id: job.agent_id,
      scheduled_at: scheduledAt,
      ...job.metadata,
    },
  };

  try {
    nc.publish(
      "smith.chatbridge.sessions.start",
      sc.encode(JSON.stringify(payload))
    );
  } catch (err) {
    log(`failed to publish session start for "${job.name}":`, err.message);
  }

  // 2. Update last_run_at and next_run_at in PG
  const nextRun = cron.nextRun();
  try {
    await pool.query(
      "UPDATE cron_jobs SET last_run_at = NOW(), next_run_at = $1 WHERE id = $2",
      [nextRun ? nextRun.toISOString() : null, job.id]
    );
  } catch (err) {
    log(`failed to update last_run_at for "${job.name}":`, err.message);
  }

  // 3. Publish audit event
  try {
    nc.publish(
      `smith.cron.fired.${job.id}`,
      sc.encode(JSON.stringify({ job_id: job.id, name: job.name, scheduled_at: scheduledAt }))
    );
  } catch (err) {
    log(`failed to publish audit event for "${job.name}":`, err.message);
  }
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
  log(`connecting to NATS at ${NATS_URL}`);
  nc = await connect({ servers: NATS_URL });
  log("NATS connected");

  // Verify PG
  try {
    await pool.query("SELECT 1");
    log("PostgreSQL connected");
  } catch (err) {
    log("PostgreSQL failed:", err.message);
  }

  // Initial load
  await loadAndSchedule();

  // Subscribe to reload signals
  const sub = nc.subscribe("smith.cron.reload");
  log("listening: smith.cron.reload");

  (async () => {
    for await (const _msg of sub) {
      log("reload signal received — reloading jobs");
      await loadAndSchedule();
    }
  })();

  log("running");
  await nc.closed();
}

main().catch((err) => {
  console.error("[smith-cron] fatal:", err);
  process.exit(1);
});
