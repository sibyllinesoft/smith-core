const http = require("node:http");
const { spawn } = require("node:child_process");

const PORT = Number(process.env.PORT || process.env.MCP_POSTGRES_PORT || 9100);
const API_TOKEN = process.env.MCP_SIDECAR_API_TOKEN || "";
const ALLOW_UNAUTHENTICATED =
  (process.env.MCP_SIDECAR_ALLOW_UNAUTHENTICATED || "false").toLowerCase() === "true";
const PSQL_PATH = process.env.PSQL_PATH || "psql";
const PSQL_URL =
  process.env.MCP_POSTGRES_PSQL_URL ||
  "postgresql://smith@envoy:15432/smith?sslmode=disable";
const QUERY_TIMEOUT_MS =
  Number(process.env.MCP_POSTGRES_QUERY_TIMEOUT_SECS || 30) * 1000;

const SERVER_INFO = {
  name: "postgres",
  version: "1.0.0",
  transport: "psql-via-pg-auth-gateway",
};

const TOOLS = [
  {
    name: "query",
    description:
      "Run a read-only SQL query against the Smith PostgreSQL database through the auth gateway. The signed Smith user identity is enforced server-side by RLS.",
    inputSchema: {
      type: "object",
      properties: {
        sql: {
          type: "string",
          description: "Read-only SQL query to execute",
        },
      },
      required: ["sql"],
      additionalProperties: false,
    },
  },
];

function extractBearer(headers) {
  const authz = headers.authorization;
  if (typeof authz === "string") {
    if (authz.startsWith("Bearer ")) {
      return authz.slice("Bearer ".length).trim();
    }
    if (authz.startsWith("bearer ")) {
      return authz.slice("bearer ".length).trim();
    }
  }

  const smithToken = headers["x-smith-token"];
  if (typeof smithToken === "string" && smithToken.trim()) {
    return smithToken.trim();
  }

  return "";
}

function extractIdentityToken(headers) {
  const token = headers["x-oc-identity-token"];
  return typeof token === "string" ? token.trim() : "";
}

function requireApiToken(req, res) {
  if (ALLOW_UNAUTHENTICATED || !API_TOKEN) {
    return true;
  }

  if (extractBearer(req.headers) === API_TOKEN) {
    return true;
  }

  sendJson(res, 401, { error: "missing or invalid API token" });
  return false;
}

function sendJson(res, statusCode, body) {
  const data = JSON.stringify(body);
  res.writeHead(statusCode, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error(`invalid JSON body: ${error.message}`));
      }
    });
    req.on("error", reject);
  });
}

function runPsql(sql, identityToken) {
  return new Promise((resolve) => {
    const args = [
      PSQL_URL,
      "--no-psqlrc",
      "--set",
      "ON_ERROR_STOP=1",
      "--csv",
      "-c",
      sql,
    ];

    const child = spawn(PSQL_PATH, args, {
      env: {
        ...process.env,
        PGPASSWORD: identityToken,
        PGAPPNAME: "smith-mcp-postgres",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, QUERY_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        error: `failed to start psql: ${error.message}`,
      });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        resolve({
          ok: false,
          error: `query timed out after ${QUERY_TIMEOUT_MS / 1000}s`,
        });
        return;
      }
      if (code === 0) {
        resolve({
          ok: true,
          output: stdout.trim() || "Query executed successfully.",
        });
        return;
      }
      const message = stderr.trim() || stdout.trim() || `psql exited with code ${code ?? "unknown"} (${signal || "no signal"})`;
      resolve({ ok: false, error: message });
    });
  });
}

async function handleToolCall(req, res) {
  if (!requireApiToken(req, res)) {
    return;
  }

  const identityToken = extractIdentityToken(req.headers);
  if (!identityToken) {
    sendJson(res, 401, { error: "missing x-oc-identity-token" });
    return;
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (error) {
    sendJson(res, 400, { error: error.message });
    return;
  }

  const sql = typeof body.sql === "string" ? body.sql.trim() : typeof body.query === "string" ? body.query.trim() : "";
  if (!sql) {
    sendJson(res, 400, { error: "body.sql must be a non-empty string" });
    return;
  }

  const result = await runPsql(sql, identityToken);
  if (result.ok) {
    sendJson(res, 200, {
      content: [{ type: "text", text: result.output }],
    });
  } else {
    sendJson(res, 400, {
      content: [{ type: "text", text: result.error }],
      isError: true,
    });
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    if (!requireApiToken(req, res)) {
      return;
    }
    sendJson(res, 200, {
      status: "ok",
      server_info: SERVER_INFO,
      tools_count: TOOLS.length,
    });
    return;
  }

  if (req.method === "GET" && req.url === "/tools") {
    if (!requireApiToken(req, res)) {
      return;
    }
    sendJson(res, 200, TOOLS);
    return;
  }

  if (req.method === "POST" && req.url === "/tools/query") {
    await handleToolCall(req, res);
    return;
  }

  sendJson(res, 404, { error: "not found" });
});

server.listen(PORT, "0.0.0.0", () => {
  console.error(`[mcp-postgres] listening on :${PORT}`);
});
