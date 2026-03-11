import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import pg from "pg";
import { z } from "zod";
import { connect, StringCodec } from "nats";
import { Cron } from "croner";

const DATABASE_URL =
  process.env.DATABASE_URL ||
  "postgresql://smith_app:__set_via_env__@postgres:5432/smith";
const GATEKEEPER_DATABASE_URL =
  process.env.GATEKEEPER_DATABASE_URL ||
  "postgresql://smith_gatekeeper:__set_via_env__@postgres:5432/smith";
const RLS_BIND_TTL_SECS = Math.max(
  1,
  Math.floor(Number(process.env.RLS_BIND_TTL_SECS || "300")) || 300
);
const NATS_URL = process.env.NATS_URL || "nats://nats:4222";

const pool = new pg.Pool({ connectionString: DATABASE_URL });
const gatekeeperPool = new pg.Pool({ connectionString: GATEKEEPER_DATABASE_URL });
const log = (...args) => console.error("[mcp-cron]", ...args);
const SmithIdentitySchema = z.object({
  user_id: z.string().optional(),
  role: z.enum(["admin", "user", "guest"]),
  channel: z.string().optional(),
  principal: z.string().optional(),
  session: z.string().optional(),
}).optional();

let nc;
let sc;

async function ensureNats() {
  if (!nc) {
    nc = await connect({ servers: NATS_URL });
    sc = StringCodec();
    log("NATS connected");
  }
  return nc;
}

async function notifyReload() {
  try {
    const conn = await ensureNats();
    conn.publish("smith.cron.reload", sc.encode(""));
    log("published smith.cron.reload");
  } catch (err) {
    log("failed to publish reload:", err.message);
  }
}

function computeNextRun(schedule) {
  try {
    const job = new Cron(schedule);
    const next = job.nextRun();
    return next ? next.toISOString() : null;
  } catch {
    return null;
  }
}

function requireSmithIdentity(identity) {
  if (!identity || !identity.role || !identity.user_id) {
    throw new Error("missing verified Smith identity");
  }

  return {
    userId: identity.user_id,
    role: identity.role,
  };
}

async function queryAsIdentity(identity, sql, params = []) {
  const { userId, role } = requireSmithIdentity(identity);
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
      [backendPid, backendStart, userId, role, RLS_BIND_TTL_SECS]
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

const server = new McpServer({
  name: "cron",
  version: "1.0.0",
});

// ── create_cron ──────────────────────────────────────────────────────

server.tool(
  "create_cron",
  "Create a scheduled cron job that starts an agent session",
  {
    name: z.string().describe("Job name"),
    schedule: z.string().describe('Cron expression, e.g. "*/5 * * * *"'),
    goal: z.string().describe("Goal text for the SessionStartRequest"),
    agent_id: z.string().optional().describe("Agent ID (default: 'default')"),
    metadata: z.record(z.any()).optional().describe("Extra metadata JSON"),
    enabled: z.boolean().optional().describe("Whether the job is enabled (default: true)"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ name, schedule, goal, agent_id, metadata, enabled, _smith_identity }) => {
    // Validate cron expression
    try {
      new Cron(schedule);
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error: invalid cron expression "${schedule}" — ${err.message}` }],
        isError: true,
      };
    }

    const nextRun = computeNextRun(schedule);
    const res = await queryAsIdentity(
      _smith_identity,
      `INSERT INTO cron_jobs (name, schedule, goal, agent_id, metadata, enabled, next_run_at, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        name,
        schedule,
        goal,
        agent_id || "default",
        JSON.stringify(metadata || {}),
        enabled !== undefined ? enabled : true,
        nextRun,
        requireSmithIdentity(_smith_identity).userId,
      ]
    );
    await notifyReload();
    return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
  }
);

// ── get_cron ─────────────────────────────────────────────────────────

server.tool(
  "get_cron",
  "Get a cron job by id",
  {
    id: z.string().describe("Cron job ID"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ id, _smith_identity }) => {
    const res = await queryAsIdentity(_smith_identity, "SELECT * FROM cron_jobs WHERE id = $1", [id]);
    if (res.rows.length === 0) {
      return { content: [{ type: "text", text: "Cron job not found" }], isError: true };
    }
    return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
  }
);

// ── list_crons ───────────────────────────────────────────────────────

server.tool(
  "list_crons",
  "List cron jobs with optional filters",
  {
    enabled: z.boolean().optional().describe("Filter by enabled status"),
    agent_id: z.string().optional().describe("Filter by agent_id"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ enabled, agent_id, _smith_identity }) => {
    const conditions = [];
    const params = [];
    if (enabled !== undefined) {
      params.push(enabled);
      conditions.push(`enabled = $${params.length}`);
    }
    if (agent_id !== undefined) {
      params.push(agent_id);
      conditions.push(`agent_id = $${params.length}`);
    }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const res = await queryAsIdentity(
      _smith_identity,
      `SELECT * FROM cron_jobs ${where} ORDER BY created_at`,
      params
    );
    return { content: [{ type: "text", text: JSON.stringify(res.rows, null, 2) }] };
  }
);

// ── update_cron ──────────────────────────────────────────────────────

server.tool(
  "update_cron",
  "Update fields of a cron job",
  {
    id: z.string().describe("Cron job ID"),
    name: z.string().optional().describe("New name"),
    schedule: z.string().optional().describe("New cron expression"),
    goal: z.string().optional().describe("New goal text"),
    agent_id: z.string().optional().describe("New agent ID"),
    metadata: z.record(z.any()).optional().describe("New metadata (merged)"),
    enabled: z.boolean().optional().describe("Enable or disable"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ id, name, schedule, goal, agent_id, metadata, enabled, _smith_identity }) => {
    // Validate new schedule if provided
    if (schedule !== undefined) {
      try {
        new Cron(schedule);
      } catch (err) {
        return {
          content: [{ type: "text", text: `Error: invalid cron expression "${schedule}" — ${err.message}` }],
          isError: true,
        };
      }
    }

    const sets = [];
    const params = [];

    if (name !== undefined) {
      params.push(name);
      sets.push(`name = $${params.length}`);
    }
    if (schedule !== undefined) {
      params.push(schedule);
      sets.push(`schedule = $${params.length}`);
      const nextRun = computeNextRun(schedule);
      params.push(nextRun);
      sets.push(`next_run_at = $${params.length}`);
    }
    if (goal !== undefined) {
      params.push(goal);
      sets.push(`goal = $${params.length}`);
    }
    if (agent_id !== undefined) {
      params.push(agent_id);
      sets.push(`agent_id = $${params.length}`);
    }
    if (metadata !== undefined) {
      params.push(JSON.stringify(metadata));
      sets.push(`metadata = metadata || $${params.length}::jsonb`);
    }
    if (enabled !== undefined) {
      params.push(enabled);
      sets.push(`enabled = $${params.length}`);
    }

    if (sets.length === 0) {
      return { content: [{ type: "text", text: "Error: no fields to update" }], isError: true };
    }

    sets.push("modified_at = NOW()");
    params.push(id);
    const query = `UPDATE cron_jobs SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`;
    const res = await queryAsIdentity(_smith_identity, query, params);
    if (res.rows.length === 0) {
      return { content: [{ type: "text", text: "Cron job not found" }], isError: true };
    }
    await notifyReload();
    return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
  }
);

// ── delete_cron ──────────────────────────────────────────────────────

server.tool(
  "delete_cron",
  "Delete a cron job by id",
  {
    id: z.string().describe("Cron job ID"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ id, _smith_identity }) => {
    const res = await queryAsIdentity(_smith_identity, "DELETE FROM cron_jobs WHERE id = $1 RETURNING *", [id]);
    if (res.rows.length === 0) {
      return { content: [{ type: "text", text: "Cron job not found" }], isError: true };
    }
    await notifyReload();
    return { content: [{ type: "text", text: `Deleted cron job "${res.rows[0].name}" (${id})` }] };
  }
);

// ── Start server ─────────────────────────────────────────────────────

async function main() {
  log("starting...");
  await ensureNats();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("connected to transport");
}

main().catch((err) => {
  log("fatal:", err);
  process.exit(1);
});
