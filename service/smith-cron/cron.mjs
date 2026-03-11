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
 *   NATS_URL       (default: nats://127.0.0.1:4222)
 *   SMITH_CRON_PG  (default: postgresql://smith_app:__set_via_env__@postgres:5432/smith)
 */

import { connect, StringCodec } from "nats";
import { createHmac } from "node:crypto";
import pg from "pg";
import { Cron } from "croner";

const NATS_URL = process.env.NATS_URL ?? "nats://127.0.0.1:4222";
const PG_URL =
  process.env.SMITH_CRON_PG ??
  "postgresql://smith_app:__set_via_env__@postgres:5432/smith";
const PG_GATEKEEPER_URL =
  process.env.SMITH_CRON_PG_GATEKEEPER ??
  "postgresql://smith_gatekeeper:__set_via_env__@postgres:5432/smith";
const PG_RLS_BIND_TTL_SECS = Math.max(
  1,
  Math.floor(Number(process.env.SMITH_CRON_PG_RLS_BIND_TTL_SECS ?? "300")) || 300
);
const IDENTITY_SECRET =
  process.env.SMITH_CRON_IDENTITY_SECRET ??
  process.env.CHAT_BRIDGE_IDENTITY_SECRET ??
  "";
const IDENTITY_TTL_SECS = Math.max(
  60,
  Math.floor(Number(process.env.SMITH_CRON_IDENTITY_TTL_SECS ?? "3600")) || 3600
);

const sc = StringCodec();
const pool = new pg.Pool({ connectionString: PG_URL, max: 3 });
const gatekeeperPool = new pg.Pool({ connectionString: PG_GATEKEEPER_URL, max: 3 });

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

function base64urlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signIdentityToken(claims) {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedClaims = base64urlEncode(JSON.stringify(claims));
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = createHmac("sha256", IDENTITY_SECRET)
    .update(signingInput)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return `${signingInput}.${signature}`;
}

function buildCronIdentity(job, owner, scheduledAt) {
  const now = Math.floor(Date.now() / 1000);
  const session = `cron:${job.id}:${scheduledAt}`;
  const claims = {
    channel: "unknown",
    principal: owner.user_id,
    session,
    display_name: owner.owner_display_name || owner.owner_username || owner.user_id,
    agent_id: job.agent_id,
    smith_user_id: owner.user_id,
    smith_user_role: owner.owner_role,
    iat: now,
    exp: now + IDENTITY_TTL_SECS,
  };

  return {
    session,
    token: signIdentityToken(claims),
    claims,
  };
}

async function queryWithBinding(userId, role, sql, params = []) {
  const client = await pool.connect();
  const gatekeeper = await gatekeeperPool.connect();
  let backendPid = null;
  let backendStart = null;
  try {
    await client.query("BEGIN");
    const binding = await client.query(
      "SELECT backend_pid, backend_start FROM public.current_backend_binding_key()"
    );
    backendPid = binding.rows[0]?.backend_pid ?? null;
    backendStart = binding.rows[0]?.backend_start ?? null;
    if (!backendPid || !backendStart) {
      throw new Error("failed to determine postgres backend binding key");
    }
    await gatekeeper.query(
      "SELECT public.bind_rls_session($1, $2, $3, $4, $5)",
      [backendPid, backendStart, userId, role, PG_RLS_BIND_TTL_SECS]
    );
    const result = await client.query(sql, params);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    if (backendPid && backendStart) {
      try {
        await gatekeeper.query(
          "SELECT public.unbind_rls_session($1, $2)",
          [backendPid, backendStart]
        );
      } catch (unbindErr) {
        log("failed to unbind RLS session:", unbindErr);
      }
    }
    gatekeeper.release();
    client.release();
  }
}

async function queryAsAdmin(sql, params = []) {
  return queryWithBinding("admin", "admin", sql, params);
}

async function queryAsOwner(owner, sql, params = []) {
  return queryWithBinding(owner.user_id, owner.owner_role, sql, params);
}

async function loadCronOwner(jobId) {
  const res = await queryAsAdmin(
    `SELECT cj.user_id,
            u.username AS owner_username,
            u.display_name AS owner_display_name,
            u.role AS owner_role,
            u.active AS owner_active
       FROM cron_jobs cj
       LEFT JOIN users u ON u.id = cj.user_id
      WHERE cj.id = $1`,
    [jobId]
  );
  return res.rows[0] ?? null;
}

async function loadAndSchedule() {
  stopAll();

  let rows;
  try {
    const res = await queryAsAdmin(
      `SELECT cj.*,
              u.username AS owner_username,
              u.display_name AS owner_display_name,
              u.role AS owner_role,
              u.active AS owner_active
         FROM cron_jobs cj
         LEFT JOIN users u ON u.id = cj.user_id
        WHERE cj.enabled = true`
    );
    rows = res.rows;
  } catch (err) {
    log("failed to load cron jobs:", err.message);
    return;
  }

  log(`loaded ${rows.length} enabled cron job(s)`);

  for (const job of rows) {
    if (!job.user_id || !job.owner_role || job.owner_active !== true) {
      log(`skipping "${job.name}" [${job.id.slice(0, 8)}]: cron owner is missing or inactive`);
      continue;
    }
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

  let owner;
  try {
    owner = await loadCronOwner(job.id);
  } catch (err) {
    log(`failed to load owner for "${job.name}":`, err.message);
    return;
  }

  if (!owner?.user_id || !owner?.owner_role || owner.owner_active !== true) {
    log(`skipping "${job.name}": cron owner is missing or inactive`);
    return;
  }

  const identity = buildCronIdentity(job, owner, scheduledAt);

  // 1. Publish SessionStartRequest
  const payload = {
    goal: job.goal,
    metadata: {
      source: "cron",
      sender_id: owner.user_id,
      sender_username: owner.owner_username,
      sender_display_name: owner.owner_display_name,
      trigger: "cron",
      cron_job_id: job.id,
      cron_name: job.name,
      agent_id: job.agent_id,
      user_id: owner.user_id,
      scheduled_at: scheduledAt,
      "x-oc-channel": identity.claims.channel,
      "x-oc-principal": identity.claims.principal,
      "x-oc-session": identity.session,
      "x-oc-smith-user-id": owner.user_id,
      "x-oc-smith-user-role": owner.owner_role,
      "x-oc-identity-token": identity.token,
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
    return;
  }

  // 2. Update last_run_at and next_run_at in PG
  const nextRun = cron.nextRun();
  try {
    await queryAsOwner(
      owner,
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
  if (!IDENTITY_SECRET.trim()) {
    throw new Error("SMITH_CRON_IDENTITY_SECRET or CHAT_BRIDGE_IDENTITY_SECRET is required");
  }
  log(`connecting to NATS at ${NATS_URL}`);
  nc = await connect({ servers: NATS_URL });
  log("NATS connected");

  // Verify PG
  try {
    await queryAsAdmin("SELECT 1");
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
