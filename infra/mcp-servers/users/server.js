import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import pg from "pg";
import { z } from "zod";

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

const pool = new pg.Pool({ connectionString: DATABASE_URL });
const gatekeeperPool = new pg.Pool({ connectionString: GATEKEEPER_DATABASE_URL });

// All logging goes to stderr (stdout is JSON-RPC transport)
const log = (...args) => console.error("[mcp-users]", ...args);
const SmithIdentitySchema = z.object({
  user_id: z.string().optional(),
  role: z.enum(["admin", "user", "guest"]),
  channel: z.string().optional(),
  principal: z.string().optional(),
  session: z.string().optional(),
}).optional();

const server = new McpServer({
  name: "users",
  version: "1.0.0",
});

function requireSmithIdentity(identity) {
  if (!identity || !identity.role) {
    throw new Error("missing verified Smith identity");
  }

  return {
    userId: identity.user_id || "",
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

// ── create_user ────────────────────────────────────────────────────────

server.tool(
  "create_user",
  "Create a new user",
  {
    username: z.string().describe("Unique username"),
    display_name: z.string().optional().describe("Display name"),
    role: z.enum(["admin", "user", "guest"]).optional().describe("User role (default: user)"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ username, display_name, role, _smith_identity }) => {
    try {
      const res = await queryAsIdentity(
        _smith_identity,
        `INSERT INTO users (username, display_name, role)
         VALUES ($1, $2, $3)
         RETURNING *`,
        [username, display_name || "", role || "user"]
      );
      return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
    } catch (err) {
      if (err.code === "23505") {
        return { content: [{ type: "text", text: `Error: username "${username}" already exists` }], isError: true };
      }
      throw err;
    }
  }
);

// ── get_user ───────────────────────────────────────────────────────────

server.tool(
  "get_user",
  "Get a user by id or username",
  {
    id: z.string().optional().describe("User ID"),
    username: z.string().optional().describe("Username"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ id, username, _smith_identity }) => {
    if (!id && !username) {
      return { content: [{ type: "text", text: "Error: provide either id or username" }], isError: true };
    }
    const col = id ? "id" : "username";
    const val = id || username;
    const res = await queryAsIdentity(_smith_identity, `SELECT * FROM users WHERE ${col} = $1`, [val]);
    if (res.rows.length === 0) {
      return { content: [{ type: "text", text: "User not found" }], isError: true };
    }
    return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
  }
);

// ── list_users ─────────────────────────────────────────────────────────

server.tool(
  "list_users",
  "List users with optional filters",
  {
    role: z.enum(["admin", "user", "guest"]).optional().describe("Filter by role"),
    active: z.boolean().optional().describe("Filter by active status"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ role, active, _smith_identity }) => {
    const conditions = [];
    const params = [];
    if (role !== undefined) {
      params.push(role);
      conditions.push(`role = $${params.length}`);
    }
    if (active !== undefined) {
      params.push(active);
      conditions.push(`active = $${params.length}`);
    }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const res = await queryAsIdentity(_smith_identity, `SELECT * FROM users ${where} ORDER BY created_at`, params);
    return { content: [{ type: "text", text: JSON.stringify(res.rows, null, 2) }] };
  }
);

// ── update_user ────────────────────────────────────────────────────────

server.tool(
  "update_user",
  "Update a user's fields",
  {
    id: z.string().describe("User ID"),
    display_name: z.string().optional().describe("New display name"),
    role: z.enum(["admin", "user", "guest"]).optional().describe("New role"),
    active: z.boolean().optional().describe("Active status"),
    config: z.record(z.any()).optional().describe("Config JSON object (merged)"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ id, display_name, role, active, config, _smith_identity }) => {
    const sets = [];
    const params = [];

    if (display_name !== undefined) {
      params.push(display_name);
      sets.push(`display_name = $${params.length}`);
    }
    if (role !== undefined) {
      params.push(role);
      sets.push(`role = $${params.length}`);
    }
    if (active !== undefined) {
      params.push(active);
      sets.push(`active = $${params.length}`);
    }
    if (config !== undefined) {
      params.push(JSON.stringify(config));
      sets.push(`config = config || $${params.length}::jsonb`);
    }

    if (sets.length === 0) {
      return { content: [{ type: "text", text: "Error: no fields to update" }], isError: true };
    }

    sets.push("modified_at = NOW()");
    params.push(id);
    const query = `UPDATE users SET ${sets.join(", ")} WHERE id = $${params.length} RETURNING *`;
    const res = await queryAsIdentity(_smith_identity, query, params);
    if (res.rows.length === 0) {
      return { content: [{ type: "text", text: "User not found" }], isError: true };
    }
    return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
  }
);

// ── add_identity ───────────────────────────────────────────────────────

server.tool(
  "add_identity",
  "Link a platform identity to a user",
  {
    user_id: z.string().describe("User ID"),
    platform: z.string().describe("Platform name (e.g. discord, slack, github)"),
    platform_user_id: z.string().describe("User ID on that platform"),
    platform_username: z.string().optional().describe("Username on that platform"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ user_id, platform, platform_user_id, platform_username, _smith_identity }) => {
    try {
      const res = await queryAsIdentity(
        _smith_identity,
        `INSERT INTO user_identities (user_id, platform, platform_user_id, platform_username)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [user_id, platform, platform_user_id, platform_username || null]
      );
      return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
    } catch (err) {
      if (err.code === "23505") {
        return {
          content: [{ type: "text", text: `Error: identity ${platform}:${platform_user_id} already linked` }],
          isError: true,
        };
      }
      if (err.code === "23503") {
        return { content: [{ type: "text", text: `Error: user "${user_id}" not found` }], isError: true };
      }
      throw err;
    }
  }
);

// ── remove_identity ────────────────────────────────────────────────────

server.tool(
  "remove_identity",
  "Remove a platform identity link",
  {
    id: z.string().describe("Identity row ID"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ id, _smith_identity }) => {
    const res = await queryAsIdentity(_smith_identity, `DELETE FROM user_identities WHERE id = $1 RETURNING *`, [id]);
    if (res.rows.length === 0) {
      return { content: [{ type: "text", text: "Identity not found" }], isError: true };
    }
    return { content: [{ type: "text", text: `Removed identity ${res.rows[0].platform}:${res.rows[0].platform_user_id}` }] };
  }
);

// ── list_identities ────────────────────────────────────────────────────

server.tool(
  "list_identities",
  "List platform identities for a user",
  {
    user_id: z.string().describe("User ID"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ user_id, _smith_identity }) => {
    const res = await queryAsIdentity(
      _smith_identity,
      `SELECT * FROM user_identities WHERE user_id = $1 ORDER BY created_at`,
      [user_id]
    );
    return { content: [{ type: "text", text: JSON.stringify(res.rows, null, 2) }] };
  }
);

// ── resolve_identity ───────────────────────────────────────────────────

server.tool(
  "resolve_identity",
  "Look up a user by platform identity",
  {
    platform: z.string().describe("Platform name (e.g. discord, slack)"),
    platform_user_id: z.string().describe("User ID on that platform"),
    _smith_identity: SmithIdentitySchema,
  },
  async ({ platform, platform_user_id, _smith_identity }) => {
    const res = await queryAsIdentity(
      _smith_identity,
      `SELECT u.*, i.platform, i.platform_user_id, i.platform_username
       FROM user_identities i
       JOIN users u ON u.id = i.user_id
       WHERE i.platform = $1 AND i.platform_user_id = $2`,
      [platform, platform_user_id]
    );
    if (res.rows.length === 0) {
      return { content: [{ type: "text", text: "No user found for that platform identity" }], isError: true };
    }
    return { content: [{ type: "text", text: JSON.stringify(res.rows[0], null, 2) }] };
  }
);

// ── Start server ───────────────────────────────────────────────────────

async function main() {
  log("starting...");
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("connected to transport");
}

main().catch((err) => {
  log("fatal:", err);
  process.exit(1);
});
