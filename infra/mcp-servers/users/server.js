import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import pg from "pg";
import { z } from "zod";

const DATABASE_URL =
  process.env.DATABASE_URL ||
  "postgresql://smith_app:smith-app-dev@postgres:5432/smith?options=-c%20app.current_user_role%3Dadmin";

const pool = new pg.Pool({ connectionString: DATABASE_URL });

// All logging goes to stderr (stdout is JSON-RPC transport)
const log = (...args) => console.error("[mcp-users]", ...args);

const server = new McpServer({
  name: "users",
  version: "1.0.0",
});

// ── create_user ────────────────────────────────────────────────────────

server.tool(
  "create_user",
  "Create a new user",
  {
    username: z.string().describe("Unique username"),
    display_name: z.string().optional().describe("Display name"),
    role: z.enum(["admin", "user", "guest"]).optional().describe("User role (default: user)"),
  },
  async ({ username, display_name, role }) => {
    try {
      const res = await pool.query(
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
  },
  async ({ id, username }) => {
    if (!id && !username) {
      return { content: [{ type: "text", text: "Error: provide either id or username" }], isError: true };
    }
    const col = id ? "id" : "username";
    const val = id || username;
    const res = await pool.query(`SELECT * FROM users WHERE ${col} = $1`, [val]);
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
  },
  async ({ role, active }) => {
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
    const res = await pool.query(`SELECT * FROM users ${where} ORDER BY created_at`, params);
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
  },
  async ({ id, display_name, role, active, config }) => {
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
    const res = await pool.query(query, params);
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
  },
  async ({ user_id, platform, platform_user_id, platform_username }) => {
    try {
      const res = await pool.query(
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
  },
  async ({ id }) => {
    const res = await pool.query(`DELETE FROM user_identities WHERE id = $1 RETURNING *`, [id]);
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
  },
  async ({ user_id }) => {
    const res = await pool.query(
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
  },
  async ({ platform, platform_user_id }) => {
    const res = await pool.query(
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
