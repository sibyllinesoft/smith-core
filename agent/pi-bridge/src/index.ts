/**
 * pi-bridge: NATS bridge between Smith chat daemon and pi-agent.
 *
 * Subscribes to `smith.chatbridge.sessions.start`, creates pi-agent sessions,
 * discovers MCP tools from mcp-index, and streams responses back via NATS.
 */

// OTel SDK must initialize before anything else
import "./tracing.js";

import { randomUUID } from "node:crypto";
import { trace, context, type Span, SpanStatusCode } from "@opentelemetry/api";
import { readFileSync } from "node:fs";
import { writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect, type NatsConnection, type Subscription, StringCodec } from "nats";
import pg from "pg";
import { Agent as UndiciAgent, fetch as undiciFetch } from "undici";
import { Agent, ProviderTransport } from "@mariozechner/pi-agent";
import { getModel } from "@mariozechner/pi-ai";
import { getEnvApiKey } from "@mariozechner/pi-ai/dist/env-api-keys.js";

const sc = StringCodec();

function envMs(name: string, fallback: number, min: number): number {
  const raw = process.env[name];
  if (raw == null || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < min) return fallback;
  return Math.floor(parsed);
}

// ── Config ────────────────────────────────────────────────────────────
const NATS_URL = process.env.SMITH_NATS_URL ?? "nats://127.0.0.1:4222";
const SESSION_START_SUBJECT = process.env.SESSION_START_SUBJECT ?? "smith.chatbridge.sessions.start";
const PROVIDER = (process.env.PI_PROVIDER ?? "anthropic") as any;
const MODEL_ID = (process.env.PI_MODEL ?? "claude-sonnet-4-5") as any;
const MCP_INDEX_URL = process.env.MCP_INDEX_URL ?? "http://localhost:9200";
const MCP_INDEX_API_TOKEN = process.env.MCP_INDEX_API_TOKEN?.trim();
const AGENTD_URL = process.env.AGENTD_URL ?? "https://localhost:6173";
const AGENTD_WORKDIR = process.env.AGENTD_WORKDIR ?? process.env.HOME ?? process.cwd();
const AGENTD_PATHS_RW = (process.env.AGENTD_PATHS_RW ?? AGENTD_WORKDIR).split(",").map(s => s.trim()).filter(Boolean);
const AGENTD_PATHS_RO = (process.env.AGENTD_PATHS_RO ?? "/etc,/usr").split(",").map(s => s.trim()).filter(Boolean);
const AGENT_ID = process.env.AGENT_ID ?? "smith-default";
const PI_SESSION_IDLE_TTL_MS = envMs("PI_SESSION_IDLE_TTL_MS", 1_800_000, 5_000);
const PI_SESSION_CLEANUP_INTERVAL_MS = envMs("PI_SESSION_CLEANUP_INTERVAL_MS", 60_000, 1_000);
const PG_URL = process.env.PI_BRIDGE_PG ?? "postgresql://smith:smith-dev@postgres:5432/smith";
const PG_APP_URL = process.env.PI_BRIDGE_PG_APP ?? "postgresql://smith_app:smith-app-dev@postgres:5432/smith";
const pgPool = new pg.Pool({ connectionString: PG_URL, max: 2 });        // superuser — identity resolution only
const pgAppPool = new pg.Pool({ connectionString: PG_APP_URL, max: 5 }); // RLS-enforced
const BASE_SYSTEM_PROMPT =
  process.env.PI_SYSTEM_PROMPT ??
  `You are Smith, an AI assistant. Your identity is '${AGENT_ID}'.

## Core Behavior

You have persistent memory via your notes system. You are not a stateless chatbot — you learn, adapt, and improve across conversations.

**At the start of every new conversation**, before responding to the user:
1. Search for your self-model note: \`notes__search\` with \`{"metadata_filter": {"type": "self"}}\`
2. Search for user model notes: \`notes__search\` with \`{"metadata_filter": {"type": "user_model"}}\`
3. Search for active tasks: \`notes__search\` with \`{"metadata_filter": {"type": "task", "status": "active"}}\`
4. Search for notes relevant to the user's message: \`notes__search\` with keywords from their request
5. Briefly review what you learn — adapt your tone, priorities, and approach accordingly.

**When context seems missing or the user references prior messages**, fetch conversation history:
- Use \`postgres__query\` to search \`chat_messages\` for this channel/thread: \`SELECT cm.role, cm.username, cm.content, cm.created_at FROM chat_messages cm JOIN chat_sessions cs ON cm.session_id = cs.id WHERE cs.channel_id = '<channel_id>' ORDER BY cm.created_at DESC LIMIT 20\`
- Use \`discord__*\` tools to read recent messages in the current channel when on Discord
- Use full-text search: \`WHERE fts @@ plainto_tsquery('search terms')\`

Do this silently. Do not narrate the process to the user unless they ask.

## Memory & Knowledge Curation

You build and maintain a model of each user and the world across interactions. **Your notes are the primary way future instances of you will understand context.** Treat note curation as a core responsibility, not an afterthought.

### What to observe and record

- **Communication style**: formal vs casual, terse vs detailed, technical depth
- **Preferences**: tools they like, workflows they follow, things they've corrected you on
- **Projects & context**: what they're working on, their goals, recurring themes
- **Feedback signals**: corrections, praise, frustration, surprise — these are high-value data
- **System knowledge**: how tools work, gotchas you discovered, useful patterns
- **Decisions and rationale**: why something was done a particular way, so it isn't re-litigated

### When to update notes

After each conversation, reflect on what you learned and update your notes:
- Update user model notes with new observations (merge, don't replace)
- Record anything surprising, challenging, or where you made a mistake — your future self needs to know
- Track decisions and their rationale
- Update your self-model if you received feedback about your behavior
- **Create reference notes** for reusable knowledge: tool patterns, common queries, system behaviors
- **Create lesson notes** when you discover something non-obvious (e.g. "Discord has a 2000-char message limit", "agentd screenshot requires a running X display")

### Note Conventions

Use metadata to categorize notes. Standard types:

| type | purpose | example |
|------|---------|---------|
| \`self\` | Your role, personality, behavioral instructions | "Smith Self-Model" |
| \`user_model\` | Observations about a specific user | "User: nathan — preferences" |
| \`task\` | Active/completed work items | "Implement auth feature" |
| \`decision\` | Architectural or design decisions with rationale | "Chose NATS over Kafka" |
| \`lesson\` | Things that were surprising, wrong, or hard-won | "pgPool needs max:3 in containers" |
| \`reference\` | Reusable knowledge, patterns, snippets | "NATS subject conventions" |

Tasks should have \`"status": "active"\`, \`"status": "done"\`, or \`"status": "blocked"\`.

Use relationships to link related notes: \`notes__link\` with URIs like \`note:ID\`, \`session:ID\`, \`agent:${AGENT_ID}\`.

### Autonomous Action

Use your user model to anticipate needs. When you have high confidence about what the user wants:
- Take action proactively rather than asking permission for low-risk operations
- Surface relevant context from your notes before the user has to ask
- Flag active tasks that are relevant to the current conversation
- Offer to continue work from previous sessions when context suggests it

When confidence is low, ask. But bias toward action — the user chose an agent, not a search engine.

## Tool Architecture

You have access to a large, dynamic set of tools. Tools come from multiple sources and are namespaced to avoid collisions.

### Tool Gateway (MCP Index)

Most tools come from **MCP servers** — external services exposed through the Smith tool gateway. Tools are namespaced as \`{server}__{tool}\` (e.g. \`github__create_issue\`, \`discord__send_message\`, \`postgres__query\`).

**Common MCP servers and what they provide:**
- **github** — Issues, PRs, repos, code search, actions
- **discord** — Send/read messages, list channels, manage guild interactions
- **slack** — Messages, channels, users
- **google** — Gmail, Calendar, Drive
- **notion** — Pages, databases, search
- **postgres** — Read-only SQL queries against the Smith database
- **users** — User CRUD, platform identity management
- **cron** — Scheduled job management
- **activitywatch** — Time tracking and activity data
- **twitter** — Posts and interactions

The available servers and tools may change. **When you need to do something and aren't sure which tool to use, search the tool catalog.** You can search your notes for tool tips, or try tool names based on the \`{server}__{tool}\` naming pattern.

### Host Tools (agentd)

You have a sandboxed execution environment via **agentd** for direct host operations:
- **Shell execution**: Run commands in an isolated sandbox
- **File operations**: Read, write, and edit files on the host filesystem
- **Screenshots**: Capture screenshots of the host display

Sandbox paths — writable: ${AGENTD_PATHS_RW.join(", ")}. Readable: ${AGENTD_PATHS_RO.join(", ")} plus all writable paths. Always use absolute paths.

### Notes (Knowledge Base)

Your persistent memory across sessions. This is how you learn, remember, and improve.
- \`notes__search\` — full-text search and/or metadata filter. **Always search before creating** to avoid duplicates.
- \`notes__create\` — create a note (title, body, metadata JSONB).
- \`notes__update\` — update title, body, or metadata by ID. Metadata is merged, not replaced.
- \`notes__delete\` — delete a note and its relationships.
- \`notes__link\` / \`notes__unlink\` — manage relationships between entities.

### Admin & Config Tools

If you have admin access, you can manage the platform itself:
- \`users__*\` — User and identity management
- \`agents__*\` — Agent profile management (model, provider, thinking level, trust)
- \`policy__*\` — OPA policy management for tool access control
- \`cron__*\` — Scheduled job management

### SQL Query Tool

\`postgres__query\` runs read-only SQL against the Smith PostgreSQL database. Use this for:
- **Conversation history**: Query \`chat_messages\` to recall what was said in past sessions
- **Session context**: Query \`chat_sessions\` to find prior conversations by channel, user, or topic
- **Advanced note queries**: Complex searches beyond what \`notes__search\` supports
- **System state**: Check users, agents, policies, cron jobs

Key tables:
- **chat_sessions** (id, agent_id, source, channel_id, thread_id, first_message, created_at, modified_at, message_count)
- **chat_messages** (id, session_id FK, agent_id, role ['user'|'assistant'|'tool_call'|'tool_result'], username, content, tool_name, tool_input JSONB, created_at) — full-text search via \`fts\` column, e.g. \`WHERE fts @@ plainto_tsquery('search terms')\`
- **notes** (id, title, body, metadata JSONB, created_by, created_at, modified_at) — full-text search via \`fts\` column
- **relationships** (id, source, target, description, created_by, created_at, modified_at)
- **users** (id, username UNIQUE, display_name, role, config JSONB, active, created_at, modified_at)
- **user_identities** (id, user_id FK→users, platform, platform_user_id, platform_username, created_at)
- **agents** (id, display_name, provider, model_id, thinking_level, system_prompt, tool_policy, trusted, max_turns, enabled, config JSONB)
- **cron_jobs** (id, name, schedule, goal, agent_id, metadata JSONB, enabled, user_id, last_run_at, next_run_at)
- **opa_policies** (policy_id, capability, entrypoint, module, data JSONB, active) — the 'tool-access' policy controls tool permissions

### Tool Discovery

When you encounter a task and aren't sure what tools are available:
1. **Think about the server name** — tools follow \`{server}__{tool}\` naming. Need to send a Discord message? Try \`discord__send_message\`.
2. **Search your notes** — you may have recorded tips about tools in previous sessions.
3. **Check the database** — \`postgres__query\` can help you understand system state.
4. **Try it** — if a tool exists, calling it will work. If it doesn't, you'll get a clear error.

Do NOT tell users you can't do something just because you aren't sure which tool to use. Explore your capabilities first.

## Style

Be concise and friendly. When you use a tool, briefly explain what you're doing. Adapt your communication style to match what you know about the user from your notes.`;

// ── User Resolution & RLS ────────────────────────────────────────────

interface ResolvedUser {
  id: string;
  username: string;
  display_name: string;
  role: "admin" | "user" | "guest";
  config: Record<string, unknown>;
}

const GUEST_USER: ResolvedUser = {
  id: "",
  username: "guest",
  display_name: "Guest",
  role: "guest",
  config: {},
};

async function resolveUser(metadata?: Record<string, unknown>): Promise<ResolvedUser | null> {
  const platform = (metadata?.source as string) ?? null;
  const platformUserId = (metadata?.sender_id as string) ?? null;
  if (!platform || !platformUserId) return null;

  try {
    const result = await pgPool.query(
      `SELECT u.id, u.username, u.display_name, u.role, u.config
       FROM users u
       JOIN user_identities ui ON ui.user_id = u.id
       WHERE ui.platform = $1 AND ui.platform_user_id = $2 AND u.active = true`,
      [platform, platformUserId]
    );
    return (result.rows[0] as ResolvedUser) ?? null;
  } catch (err) {
    console.error(`[pi-bridge] resolveUser failed:`, err);
    return null;
  }
}

async function queryAsUser(userId: string, role: string, sql: string, params: any[]): Promise<pg.QueryResult> {
  const client = await pgAppPool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL app.current_user_id = $1", [userId]);
    await client.query("SET LOCAL app.current_user_role = $1", [role]);
    const result = await client.query(sql, params);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// ── Tool filtering by OPA policy ─────────────────────────────────────
//
// All tool access decisions go through OPA. On successful policy fetch we
// cache the policy data so that if OPA is temporarily unreachable we can
// evaluate locally using the same Rego-managed data — no hardcoded defaults.

const OPA_URL = process.env.OPA_URL ?? "http://opa-management:8181";

interface OpaToolAccessData {
  roles: Record<string, { default: "allow" | "deny"; exceptions: Record<string, boolean> }>;
  user_overrides: Record<string, { default?: "allow" | "deny"; tools?: Record<string, "allow" | "deny"> }>;
}

let cachedPolicyData: OpaToolAccessData | null = null;

async function refreshPolicyCache(): Promise<OpaToolAccessData | null> {
  try {
    const resp = await fetch(`${OPA_URL}/v1/data/smith/tool_access`, {
      method: "GET",
      headers: { "content-type": "application/json" },
    });
    const body = await resp.json() as { result?: OpaToolAccessData };
    if (body.result) {
      cachedPolicyData = body.result;
      return cachedPolicyData;
    }
  } catch (err) {
    console.warn("[pi-bridge] OPA policy cache refresh failed:", (err as Error).message);
  }
  return cachedPolicyData;
}

function evaluateToolLocally(
  userId: string,
  role: string,
  toolName: string,
  policy: OpaToolAccessData,
): boolean {
  // Check user-level overrides first (mirrors Rego precedence)
  const userOverride = policy.user_overrides?.[userId];
  if (userOverride) {
    const toolRule = userOverride.tools?.[toolName];
    if (toolRule !== undefined) return toolRule === "allow";
    if (userOverride.default !== undefined) return userOverride.default === "allow";
  }

  // Fall back to role-based rules
  const roleCfg = policy.roles?.[role] ?? policy.roles?.guest;
  if (!roleCfg) return false;
  const isException = roleCfg.exceptions?.[toolName] === true;
  return roleCfg.default === "allow" ? !isException : isException;
}

interface ToolAccessContext {
  user_id: string;
  username: string;
  role: string;
  agent_id: string;
  source: string;
  channel_id: string;
  thread_id: string;
  trigger: string;
  metadata: Record<string, unknown>;
}

async function evaluateToolAccess(
  ctx: ToolAccessContext,
  tools: any[],
): Promise<any[]> {
  try {
    const results = await Promise.all(
      tools.map(async (tool) => {
        const resp = await fetch(`${OPA_URL}/v1/data/smith/tool_access/allow`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ input: { ...ctx, tool: tool.name } }),
        });
        const data = await resp.json() as { result?: boolean };
        return data.result === true ? tool : null;
      })
    );
    const allowed = results.filter(Boolean);
    if (allowed.length > 0) {
      // Successful OPA eval — refresh cache in background
      refreshPolicyCache().catch(() => {});
      return allowed;
    }
  } catch (err) {
    console.warn("[pi-bridge] OPA tool access eval failed, using cached policy:", (err as Error).message);
  }

  // OPA unreachable or returned no results — evaluate from cached policy data
  if (cachedPolicyData) {
    console.warn("[pi-bridge] Evaluating tool access from cached OPA policy data");
    return tools.filter((tool) => evaluateToolLocally(ctx.user_id, ctx.role, tool.name, cachedPolicyData!));
  }

  // No cache available — deny all (secure default)
  console.error("[pi-bridge] No OPA connection and no cached policy — denying all tools");
  return [];
}

// Warm the policy cache on module load
refreshPolicyCache().catch(() => {});

// ── Agent profile resolution (DB-driven) ────────────────────────────
//
// Precedence: per-user users.config > agent profile from DB > env var fallback.

interface AgentProfile {
  id: string;
  display_name: string;
  provider: string;
  model_id: string;
  thinking_level: string;
  system_prompt: string | null;
  tool_policy: string;
  trusted: boolean;
  max_turns: number | null;
  config: Record<string, unknown>;
}

const DEFAULT_AGENT_PROFILE: AgentProfile = {
  id: "default",
  display_name: "Smith",
  provider: PROVIDER,
  model_id: MODEL_ID,
  thinking_level: "off",
  system_prompt: null,
  tool_policy: "tool-access",
  trusted: true,
  max_turns: null,
  config: {},
};

async function loadAgentProfile(agentId: string): Promise<AgentProfile> {
  try {
    const res = await pgPool.query(
      "SELECT * FROM agents WHERE id = $1 AND enabled = true",
      [agentId]
    );
    if (res.rows.length > 0) {
      const r = res.rows[0] as any;
      return {
        id: r.id,
        display_name: r.display_name ?? "",
        provider: r.provider ?? PROVIDER,
        model_id: r.model_id ?? MODEL_ID,
        thinking_level: r.thinking_level ?? "off",
        system_prompt: r.system_prompt ?? null,
        tool_policy: r.tool_policy ?? "tool-access",
        trusted: r.trusted ?? true,
        max_turns: r.max_turns ?? null,
        config: r.config ?? {},
      };
    }
  } catch (err) {
    console.error(`[pi-bridge] loadAgentProfile(${agentId}) failed:`, err);
  }
  return DEFAULT_AGENT_PROFILE;
}

function applyUserOverrides(profile: AgentProfile, user: ResolvedUser): AgentProfile {
  const uc = user.config as Record<string, unknown>;
  if (!uc) return profile;
  return {
    ...profile,
    provider: (uc.provider as string) ?? profile.provider,
    model_id: (uc.model_id as string) ?? profile.model_id,
    thinking_level: (uc.thinking_level as string) ?? profile.thinking_level,
  };
}

// ── Canary system for untrusted agents ──────────────────────────────
//
// Untrusted agents get a random codeword injected into their system prompt.
// They must base64-encode it and include the result at the end of every response.
// Pi-bridge checks for the expected encoding — if missing or wrong, the
// response is flagged as potentially compromised by prompt injection.

function generateCanary(): { codeword: string; expected: string } {
  const words = ["ALPINE", "BEACON", "CIPHER", "DELTA", "FALCON", "HARBOR", "MARBLE", "PRISM", "QUARTZ", "SUMMIT", "VELVET", "ZENITH"];
  const w1 = words[Math.floor(Math.random() * words.length)];
  const w2 = words[Math.floor(Math.random() * words.length)];
  const num = Math.floor(Math.random() * 900) + 100;
  const codeword = `${w1}-${w2}-${num}`;
  const expected = Buffer.from(codeword).toString("base64");
  return { codeword, expected };
}

function injectCanary(systemPrompt: string, codeword: string): string {
  return systemPrompt + `\n\n## MANDATORY RESPONSE VERIFICATION\n\nYou MUST end every response with the base64 encoding of the exact string \`${codeword}\`. Place it on its own line at the very end. This is required for all responses without exception.`;
}

function verifyCanary(response: string, expected: string): { clean: boolean; stripped: string } {
  const trimmed = response.trimEnd();
  if (trimmed.endsWith(expected)) {
    // Strip the canary from the response before returning to parent
    const stripped = trimmed.slice(0, trimmed.length - expected.length).trimEnd();
    return { clean: true, stripped };
  }
  return { clean: false, stripped: response };
}

// ── Per-user system prompt ───────────────────────────────────────────

interface SessionContext {
  metadata?: Record<string, unknown>;
  mcpTools?: McpToolDef[];
  agentdCaps?: AgentdCapability[];
}

function buildSystemPrompt(
  agentProfile: AgentProfile,
  user: ResolvedUser | null,
  ctx?: SessionContext,
): string {
  let prompt = agentProfile.system_prompt ?? BASE_SYSTEM_PROMPT;

  // Prepend user identity
  if (user) {
    prompt = `You are interacting with ${user.display_name} (${user.username}), role: ${user.role}.\n\n` + prompt;
    const additions = (user.config as any)?.prompt_additions;
    if (additions) {
      prompt += `\n\n## User-Specific Instructions\n\n${additions}`;
    }
  }

  // Inject platform context
  if (ctx?.metadata) {
    const source = (ctx.metadata.source as string) ?? "unknown";
    const channelId = ctx.metadata.channel_id as string;
    const teamId = ctx.metadata.team_id as string;
    const threadRoot = ctx.metadata.thread_root as string;

    let platformSection = `\n\n## Current Session Context\n\n`;
    platformSection += `**Platform**: ${source}`;
    if (channelId) platformSection += ` | **Channel**: ${channelId}`;
    if (teamId) platformSection += ` | **Server/Team**: ${teamId}`;
    if (threadRoot) platformSection += ` | **Thread**: ${threadRoot}`;
    platformSection += `\n`;

    if (source === "discord") {
      platformSection += `\nYou are communicating via **Discord**. Keep in mind:\n`;
      platformSection += `- Messages are limited to 2000 characters (long responses will be split automatically)\n`;
      platformSection += `- You can use Discord markdown (bold, italic, code blocks, etc.)\n`;
      platformSection += `- Users may share images/files as attachments in the conversation\n`;
      platformSection += `- "This thread/channel" refers to the Discord channel you are in\n`;
      platformSection += `- You have \`discord__*\` tools to interact with Discord (send messages, read history, list channels)\n`;
    } else if (source === "mattermost") {
      platformSection += `\nYou are communicating via **Mattermost**.\n`;
      platformSection += `- You can use Mattermost markdown formatting\n`;
      platformSection += `- "This thread/channel" refers to the Mattermost channel you are in\n`;
    }

    // Attachment context
    const attachments = ctx.metadata.attachments as any[];
    if (attachments?.length) {
      platformSection += `\n**Attachments in this message**: ${attachments.map((a: any) => `${a.name} (${a.mime_type ?? "unknown type"}, ${a.size_bytes} bytes)`).join(", ")}\n`;
    }

    prompt += platformSection;
  }

  // Inject dynamic tool catalog summary
  if (ctx?.mcpTools?.length) {
    const serverCounts: Record<string, number> = {};
    for (const t of ctx.mcpTools) {
      serverCounts[t.server] = (serverCounts[t.server] ?? 0) + 1;
    }
    let catalogSection = `\n\n## Active Tool Catalog\n\n`;
    catalogSection += `You currently have **${ctx.mcpTools.length} MCP tools** from **${Object.keys(serverCounts).length} servers**:\n\n`;
    for (const [server, count] of Object.entries(serverCounts).sort()) {
      catalogSection += `- **${server}**: ${count} tool${count > 1 ? "s" : ""}\n`;
    }
    prompt += catalogSection;
  }

  // Inject agentd capabilities
  if (ctx?.agentdCaps?.length) {
    let agentdSection = `\n\n**agentd capabilities**: ${ctx.agentdCaps.map(c => `\`agentd__${c.name}\``).join(", ")}\n`;
    prompt += agentdSection;
  }

  return prompt;
}

const tracer = trace.getTracer("pi-bridge");

// ── mTLS dispatcher for Envoy gateway ────────────────────────────────
function createMtlsDispatcher(): UndiciAgent | undefined {
  const certPath = process.env.CLIENT_CERT ?? "/etc/smith/certs/client.crt";
  const keyPath = process.env.CLIENT_KEY ?? "/etc/smith/certs/client.key";
  const caPath = process.env.CA_CERT ?? "/etc/smith/certs/ca.crt";

  try {
    const cert = readFileSync(certPath);
    const key = readFileSync(keyPath);
    const ca = readFileSync(caPath);
    console.log(`[pi-bridge] mTLS certs loaded from ${certPath}`);
    return new UndiciAgent({
      connect: {
        cert,
        key,
        ca,
        rejectUnauthorized: process.env.AGENTD_TLS_VERIFY !== "false",
      },
    });
  } catch (err) {
    console.warn(`[pi-bridge] mTLS certs not found, agentd calls will use default TLS:`, (err as Error).message);
    return undefined;
  }
}

const mtlsDispatcher = createMtlsDispatcher();

// ── Types ─────────────────────────────────────────────────────────────
interface ThreadHistoryMessage {
  role: string;
  content: string;
  username?: string;
  timestamp?: string;
}

interface SessionStartRequest {
  goal: string;
  metadata?: Record<string, unknown>;
  immediate?: boolean;
  thread_history?: ThreadHistoryMessage[];
}

interface SessionStartResponse {
  request_id: string;
  session_id: string;
  steering_subject: string;
  trace_id: string;
  response_subject: string;
}

interface SteeringMessage {
  content: string;
  role: string;
  metadata?: Record<string, unknown>;
}

interface AgentSession {
  agent: Agent;
  steeringSub: Subscription;
  responseSubject: string;
  agentd: AgentdRef;
  canaryExpected: string | null;
  sessionSpan: Span;
  turnCount: number;
  user: ResolvedUser;
  lastActiveAt: number;
}

interface McpToolDef {
  name: string;
  server: string;
  description?: string;
  input_schema?: any;
}

function mcpIndexHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...extra };
  if (MCP_INDEX_API_TOKEN) {
    headers.authorization = `Bearer ${MCP_INDEX_API_TOKEN}`;
  }
  return headers;
}

// ── MCP Tool Discovery ───────────────────────────────────────────────

async function fetchMcpTools(): Promise<McpToolDef[]> {
  try {
    const resp = await fetch(`${MCP_INDEX_URL}/api/tools`, {
      headers: mcpIndexHeaders(),
    });
    if (!resp.ok) {
      console.warn(`[pi-bridge] Failed to fetch MCP tools: ${resp.status}`);
      return [];
    }
    const tools: McpToolDef[] = await resp.json();
    return tools;
  } catch (err) {
    console.warn(`[pi-bridge] MCP index unreachable at ${MCP_INDEX_URL}:`, err);
    return [];
  }
}

function buildAgentTools(mcpTools: McpToolDef[]): any[] {
  return mcpTools.map((tool) => {
    // Namespace tool name with server to avoid collisions
    const qualifiedName = `${tool.server}__${tool.name}`;

    return {
      name: qualifiedName,
      label: `${tool.server}/${tool.name}`,
      description: tool.description ?? `MCP tool: ${tool.server}/${tool.name}`,
      parameters: tool.input_schema ?? { type: "object", properties: {} },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] Tool call: ${tool.server}/${tool.name}`, JSON.stringify(params).slice(0, 200));
        try {
          const resp = await fetch(`${MCP_INDEX_URL}/api/tools/call`, {
            method: "POST",
            headers: mcpIndexHeaders({ "content-type": "application/json" }),
            body: JSON.stringify({
              server: tool.server,
              tool: tool.name,
              arguments: params,
            }),
          });
          const body = await resp.text();
          if (!resp.ok) {
            console.error(`[pi-bridge] Tool error ${resp.status}: ${body.slice(0, 300)}`);
            return {
              content: [{ type: "text" as const, text: `Error (${resp.status}): ${body.slice(0, 1000)}` }],
              details: undefined,
            };
          }
          console.log(`[pi-bridge] Tool result: ${body.length} chars`);
          return {
            content: [{ type: "text" as const, text: body.slice(0, 50000) }],
            details: undefined,
          };
        } catch (err) {
          console.error(`[pi-bridge] Tool fetch error:`, err);
          return {
            content: [{ type: "text" as const, text: `Tool call failed: ${err}` }],
            details: undefined,
          };
        }
      },
    };
  });
}

// ── Agentd Tool Discovery & Execution ────────────────────────────────

interface AgentdCapability {
  name: string;
  description: string;
  version: number;
  param_schema_json: string;
  requires_elevated: boolean;
  supports_streaming: boolean;
  tags: string[];
}

interface PendingAttachment {
  url: string;
  title: string;
  mime_type: string;
}

interface AgentdRef {
  sandboxId: string | null;
  pendingAttachments: PendingAttachment[];
}

function agentdFetch(path: string, body: unknown): Promise<globalThis.Response> {
  const url = `${AGENTD_URL}${path}`;
  return undiciFetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    dispatcher: mtlsDispatcher,
  }) as Promise<globalThis.Response>;
}

async function fetchAgentdCapabilities(): Promise<AgentdCapability[]> {
  try {
    const resp = await agentdFetch("/agentd.v1.Agentd/ListCapabilities", {});
    if (!resp.ok) {
      console.warn(`[pi-bridge] Failed to fetch agentd capabilities: ${resp.status}`);
      return [];
    }
    const data = await resp.json() as { capabilities?: AgentdCapability[] };
    return data.capabilities ?? [];
  } catch (err) {
    console.warn(`[pi-bridge] agentd unreachable at ${AGENTD_URL}:`, (err as Error).message);
    return [];
  }
}

async function createAgentdSandbox(): Promise<string | null> {
  try {
    const resp = await agentdFetch("/agentd.v1.Agentd/CreateSandbox", {
      profile: "default",
      workdir: AGENTD_WORKDIR,
      allowed_paths_rw: AGENTD_PATHS_RW,
      allowed_paths_ro: AGENTD_PATHS_RO,
      network_enabled: true,
    });
    if (!resp.ok) {
      console.warn(`[pi-bridge] Failed to create agentd sandbox: ${resp.status}`);
      return null;
    }
    const data = await resp.json() as { sandbox_id?: string };
    return data.sandbox_id ?? null;
  } catch (err) {
    console.warn(`[pi-bridge] agentd sandbox creation failed:`, (err as Error).message);
    return null;
  }
}

// Capabilities known to produce image data in output_json
const IMAGE_CAPABILITIES = new Set(["screenshot.capture.v1"]);

/**
 * Detect base64 image data in an agentd capability result, save to a temp file,
 * and return attachment metadata.  Returns null if no image was found.
 */
async function extractImageAttachment(
  capName: string,
  outputJson: string,
): Promise<(PendingAttachment & { summary: string }) | null> {
  try {
    let base64Data: string | null = null;
    let mimeType = "image/png";
    let summary = "Image captured";

    // Try parsing as JSON with an image data field
    try {
      const parsed = JSON.parse(outputJson);
      if (typeof parsed === "object" && parsed !== null) {
        const imageData = parsed.image ?? parsed.data ?? parsed.screenshot ?? parsed.content;
        if (typeof imageData === "string" && imageData.length > 256) {
          base64Data = imageData;
          if (parsed.format) mimeType = `image/${parsed.format}`;
          if (parsed.mime_type) mimeType = parsed.mime_type;
          const parts: string[] = [];
          if (parsed.width) parts.push(`${parsed.width}x${parsed.height ?? "?"}`);
          if (parsed.format) parts.push(parsed.format);
          summary = parts.length ? `Screenshot captured (${parts.join(", ")})` : "Screenshot captured";
        }
      }
    } catch {
      // Not valid JSON — check for raw base64 image data on known image capabilities
      if (IMAGE_CAPABILITIES.has(capName)) {
        const trimmed = outputJson.trim();
        const dataUriMatch = trimmed.match(/^data:(image\/[^;]+);base64,(.+)$/s);
        if (dataUriMatch) {
          mimeType = dataUriMatch[1];
          base64Data = dataUriMatch[2];
        } else if (trimmed.startsWith("iVBOR")) {
          base64Data = trimmed;
          mimeType = "image/png";
        } else if (trimmed.startsWith("/9j/")) {
          base64Data = trimmed;
          mimeType = "image/jpeg";
        }
      }
    }

    if (!base64Data) return null;

    // Strip nested data-URI prefix if present
    const innerMatch = base64Data.match(/^data:(image\/[^;]+);base64,(.+)$/s);
    if (innerMatch) {
      mimeType = innerMatch[1];
      base64Data = innerMatch[2];
    }

    const ext = mimeType.split("/")[1]?.replace("+xml", "") || "png";
    const filename = `${capName.replace(/\./g, "_")}_${randomUUID().slice(0, 8)}.${ext}`;
    const dir = join(tmpdir(), "smith-attachments");
    await mkdir(dir, { recursive: true });
    const filepath = join(dir, filename);
    await writeFile(filepath, Buffer.from(base64Data, "base64"));
    console.log(`[pi-bridge] Saved image attachment: ${filepath} (${mimeType})`);

    return { url: `file://${filepath}`, title: filename, mime_type: mimeType, summary };
  } catch (err) {
    console.warn(`[pi-bridge] Failed to extract image attachment:`, err);
    return null;
  }
}

function buildAgentdCapabilityTools(capabilities: AgentdCapability[], sessionRef: AgentdRef): any[] {
  return capabilities.map((cap) => {
    let paramSchema: any = { type: "object", properties: {} };
    if (cap.param_schema_json) {
      try {
        paramSchema = JSON.parse(cap.param_schema_json);
      } catch { /* use default */ }
    }

    return {
      name: `agentd__${cap.name}`,
      label: `agentd/${cap.name}`,
      description: cap.description || `agentd capability: ${cap.name}`,
      parameters: paramSchema,
      execute: async (_toolCallId: string, params: any) => {
        // Auto-inject AT-SPI bus address for desktop capabilities
        const uiCaps = ["accessibility.query.v1", "ui.windows.list.v1", "ui.node.inspect.v1", "screenshot.capture.v1"];
        if (uiCaps.includes(cap.name) && !params.dbus_address) {
          params = { ...params, dbus_address: process.env.AT_SPI2_BUS_ADDRESS ?? "unix:path=/run/user/1000/at-spi/bus_1" };
        }
        console.log(`[pi-bridge] agentd Execute: ${cap.name}`, JSON.stringify(params).slice(0, 200));
        try {
          const resp = await agentdFetch("/agentd.v1.Agentd/Execute", {
            request_id: randomUUID(),
            capability: cap.name,
            params_json: JSON.stringify(params),
            sandbox_prefs: {
              sandbox_id: sessionRef.sandboxId ?? "",
              persist: true,
            },
          });
          // gRPC errors come back with empty body and error in grpc-message header
          const contentLength = resp.headers.get("content-length");
          if (!resp.ok && (contentLength === "0" || contentLength === null)) {
            const grpcMsg = decodeURIComponent(resp.headers.get("grpc-message") ?? `HTTP ${resp.status}`);
            console.error(`[pi-bridge] agentd Execute gRPC error: ${grpcMsg}`);
            return {
              content: [{ type: "text" as const, text: `Error: ${grpcMsg}` }],
              details: undefined,
            };
          }
          const body = await resp.json() as any;
          if (!resp.ok || body.error) {
            const errMsg = body.error?.message ?? body.message ?? `HTTP ${resp.status}`;
            console.error(`[pi-bridge] agentd Execute error: ${errMsg}`);
            return {
              content: [{ type: "text" as const, text: `Error: ${errMsg}` }],
              details: undefined,
            };
          }
          // Build result text from the execution result
          const result = body.result ?? {};
          const parts: string[] = [];
          if (result.stdout) parts.push(result.stdout);
          if (result.stderr) parts.push(`stderr: ${result.stderr}`);
          // Check for image data in output_json before adding as text
          if (result.output_json) {
            const imgAttachment = await extractImageAttachment(cap.name, result.output_json);
            if (imgAttachment) {
              sessionRef.pendingAttachments.push({
                url: imgAttachment.url,
                title: imgAttachment.title,
                mime_type: imgAttachment.mime_type,
              });
              parts.push(imgAttachment.summary);
            } else {
              parts.push(result.output_json);
            }
          }
          if (result.exit_code !== undefined && result.exit_code !== 0) {
            parts.push(`exit code: ${result.exit_code}`);
          }
          const text = parts.join("\n") || "(no output)";
          console.log(`[pi-bridge] agentd Execute result: ${text.length} chars`);
          return {
            content: [{ type: "text" as const, text: text.slice(0, 50000) }],
            details: undefined,
          };
        } catch (err) {
          console.error(`[pi-bridge] agentd Execute fetch error:`, err);
          return {
            content: [{ type: "text" as const, text: `agentd call failed: ${err}` }],
            details: undefined,
          };
        }
      },
    };
  });
}

function buildAgentdFileTools(sessionRef: AgentdRef): any[] {
  return [
    {
      name: "agentd__read_file",
      label: "agentd/read_file",
      description: "Read file contents from the host filesystem (sandboxed)",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute path to the file to read" },
          offset: { type: "number", description: "Byte offset to start reading from (optional)" },
          limit: { type: "number", description: "Maximum bytes to read, 0 for no limit (optional)" },
        },
        required: ["path"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agentd ReadFile: ${params.path}`);
        try {
          const resp = await agentdFetch("/agentd.v1.Agentd/ReadFile", {
            sandbox_id: sessionRef.sandboxId ?? "",
            path: params.path,
            offset: params.offset ?? 0,
            limit: params.limit ?? 0,
          });
          const body = await resp.json() as any;
          if (!resp.ok || !body.success) {
            const errMsg = body.error ?? `HTTP ${resp.status}`;
            return {
              content: [{ type: "text" as const, text: `Error reading file: ${errMsg}` }],
              details: undefined,
            };
          }
          let text = body.content ?? "";
          if (body.truncated) text += "\n[truncated]";
          console.log(`[pi-bridge] agentd ReadFile result: ${text.length} chars`);
          return {
            content: [{ type: "text" as const, text: text.slice(0, 50000) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `ReadFile failed: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "agentd__write_file",
      label: "agentd/write_file",
      description: "Write or create a file on the host filesystem (sandboxed)",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute path to the file to write" },
          content: { type: "string", description: "Content to write to the file" },
          create_dirs: { type: "boolean", description: "Create parent directories if needed" },
          append: { type: "boolean", description: "Append instead of overwrite" },
        },
        required: ["path", "content"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agentd WriteFile: ${params.path}`);
        try {
          const resp = await agentdFetch("/agentd.v1.Agentd/WriteFile", {
            sandbox_id: sessionRef.sandboxId ?? "",
            path: params.path,
            content: params.content,
            create_dirs: params.create_dirs ?? true,
            append: params.append ?? false,
          });
          const body = await resp.json() as any;
          if (!resp.ok || !body.success) {
            const errMsg = body.error ?? `HTTP ${resp.status}`;
            return {
              content: [{ type: "text" as const, text: `Error writing file: ${errMsg}` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Wrote ${body.bytes_written ?? 0} bytes to ${params.path}` }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `WriteFile failed: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "agentd__edit_file",
      label: "agentd/edit_file",
      description: "Search and replace text in a file on the host filesystem (sandboxed)",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute path to the file to edit" },
          old_string: { type: "string", description: "Text to find and replace" },
          new_string: { type: "string", description: "Replacement text" },
          replace_all: { type: "boolean", description: "Replace all occurrences (default: false)" },
        },
        required: ["path", "old_string", "new_string"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agentd EditFile: ${params.path}`);
        try {
          const resp = await agentdFetch("/agentd.v1.Agentd/EditFile", {
            sandbox_id: sessionRef.sandboxId ?? "",
            path: params.path,
            old_string: params.old_string,
            new_string: params.new_string,
            replace_all: params.replace_all ?? false,
          });
          const body = await resp.json() as any;
          if (!resp.ok || !body.success) {
            const errMsg = body.error ?? `HTTP ${resp.status}`;
            return {
              content: [{ type: "text" as const, text: `Error editing file: ${errMsg}` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Made ${body.replacements_made ?? 0} replacement(s) in ${params.path}` }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `EditFile failed: ${err}` }],
            details: undefined,
          };
        }
      },
    },
  ];
}

// ── Notes & Relationships Tools ──────────────────────────────────────

function buildNoteTools(user: ResolvedUser): any[] {
  const q = (sql: string, params: any[]) => queryAsUser(user.id, user.role, sql, params);

  return [
    {
      name: "notes__create",
      label: "notes/create",
      description: "Create a new note in the knowledge base. Returns the note ID.",
      parameters: {
        type: "object",
        properties: {
          title: { type: "string", description: "Note title" },
          body: { type: "string", description: "Note content (markdown)" },
          metadata: { type: "object", description: "Optional JSON metadata (tags, category, etc.)" },
        },
        required: ["title"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] notes__create: "${params.title}"`);
        try {
          const id = randomUUID();
          await q(
            `INSERT INTO notes (id, title, body, metadata, created_by, user_id)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [id, params.title, params.body ?? "", params.metadata ? JSON.stringify(params.metadata) : "{}", AGENT_ID, user.id]
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify({ id, title: params.title }) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error creating note: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "notes__update",
      label: "notes/update",
      description: "Update an existing note. Only provided fields are changed.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Note ID to update" },
          title: { type: "string", description: "New title (optional)" },
          body: { type: "string", description: "New body content (optional)" },
          metadata: { type: "object", description: "New metadata — merged with existing (optional)" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] notes__update: ${params.id}`);
        try {
          const sets: string[] = ["modified_at = NOW()"];
          const vals: any[] = [];
          let idx = 1;

          if (params.title !== undefined) {
            sets.push(`title = $${idx++}`);
            vals.push(params.title);
          }
          if (params.body !== undefined) {
            sets.push(`body = $${idx++}`);
            vals.push(params.body);
          }
          if (params.metadata !== undefined) {
            sets.push(`metadata = metadata || $${idx++}::jsonb`);
            vals.push(JSON.stringify(params.metadata));
          }
          vals.push(params.id);

          const result = await q(
            `UPDATE notes SET ${sets.join(", ")} WHERE id = $${idx}`,
            vals
          );
          if (result.rowCount === 0) {
            return {
              content: [{ type: "text" as const, text: `Note not found: ${params.id}` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Updated note ${params.id}` }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error updating note: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "notes__delete",
      label: "notes/delete",
      description: "Delete a note and its relationships.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Note ID to delete" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] notes__delete: ${params.id}`);
        try {
          const uri = `note:${params.id}`;
          await q(
            `DELETE FROM relationships WHERE source = $1 OR target = $1`,
            [uri]
          );
          const result = await q(
            `DELETE FROM notes WHERE id = $1`,
            [params.id]
          );
          if (result.rowCount === 0) {
            return {
              content: [{ type: "text" as const, text: `Note not found: ${params.id}` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Deleted note ${params.id}` }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error deleting note: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "notes__link",
      label: "notes/link",
      description: "Create a relationship between two entities (notes, sessions, agents, etc.).",
      parameters: {
        type: "object",
        properties: {
          source: { type: "string", description: "Source entity URI (e.g. 'note:abc', 'session:xyz', 'agent:smith-default')" },
          target: { type: "string", description: "Target entity URI" },
          description: { type: "string", description: "Relationship description (e.g. 'related to', 'blocks', 'parent of')" },
        },
        required: ["source", "target"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] notes__link: ${params.source} → ${params.target}`);
        try {
          const id = randomUUID();
          await q(
            `INSERT INTO relationships (id, source, target, description, created_by, user_id)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [id, params.source, params.target, params.description ?? "", AGENT_ID, user.id]
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify({ id, source: params.source, target: params.target }) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error creating link: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "notes__unlink",
      label: "notes/unlink",
      description: "Remove a relationship by its ID.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Relationship ID to delete" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] notes__unlink: ${params.id}`);
        try {
          const result = await q(
            `DELETE FROM relationships WHERE id = $1`,
            [params.id]
          );
          if (result.rowCount === 0) {
            return {
              content: [{ type: "text" as const, text: `Relationship not found: ${params.id}` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Deleted relationship ${params.id}` }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error deleting link: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "notes__search",
      label: "notes/search",
      description: "Search notes by full-text query and/or metadata filters. Returns matching notes with titles, bodies, and metadata.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Full-text search query (optional if metadata_filter is provided)" },
          metadata_filter: { type: "object", description: "Filter by metadata keys (e.g. {\"type\": \"user_model\"}) — exact match on each key" },
          limit: { type: "number", description: "Max results (default 20)" },
        },
      },
      execute: async (_toolCallId: string, params: any) => {
        const qry = params.query?.trim();
        const metaFilter = params.metadata_filter;
        const limit = Math.min(params.limit ?? 20, 50);
        console.log(`[pi-bridge] notes__search: q="${qry ?? ""}" meta=${JSON.stringify(metaFilter ?? {})}`);
        try {
          let sql: string;
          const vals: any[] = [];
          let idx = 1;

          if (qry) {
            sql = `SELECT n.id, n.title, n.body, n.metadata, n.created_by, n.created_at, n.modified_at,
                     ts_rank(n.fts, plainto_tsquery('english', $${idx})) AS rank
                   FROM notes n
                   WHERE n.fts @@ plainto_tsquery('english', $${idx})`;
            vals.push(qry);
            idx++;
          } else {
            sql = `SELECT n.id, n.title, n.body, n.metadata, n.created_by, n.created_at, n.modified_at,
                     0::float AS rank
                   FROM notes n WHERE 1=1`;
          }

          if (metaFilter && typeof metaFilter === "object") {
            sql += ` AND n.metadata @> $${idx}::jsonb`;
            vals.push(JSON.stringify(metaFilter));
            idx++;
          }

          sql += qry ? ` ORDER BY rank DESC` : ` ORDER BY n.modified_at DESC`;
          sql += ` LIMIT $${idx}`;
          vals.push(limit);

          const result = await q(sql, vals);

          // Also fetch relationships for returned notes
          const noteIds = result.rows.map((r: any) => `note:${r.id}`);
          let rels: any[] = [];
          if (noteIds.length > 0) {
            const relResult = await q(
              `SELECT id, source, target, description FROM relationships
               WHERE source = ANY($1) OR target = ANY($1)`,
              [noteIds]
            );
            rels = relResult.rows;
          }

          const output = {
            notes: result.rows.map((r: any) => ({
              id: r.id,
              title: r.title,
              body: r.body.length > 2000 ? r.body.slice(0, 2000) + "..." : r.body,
              metadata: r.metadata,
              created_by: r.created_by,
              created_at: r.created_at,
              modified_at: r.modified_at,
            })),
            relationships: rels,
            total: result.rows.length,
          };

          return {
            content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error searching notes: ${err}` }],
            details: undefined,
          };
        }
      },
    },
  ];
}

// ── User Management Tools (admin-only) ───────────────────────────────

function buildUserManagementTools(user: ResolvedUser): any[] {
  if (user.role !== "admin") return [];
  const q = (sql: string, params: any[]) => queryAsUser(user.id, user.role, sql, params);

  return [
    {
      name: "users__list",
      label: "users/list",
      description: "List users with optional filters. Returns users with linked identity counts.",
      parameters: {
        type: "object",
        properties: {
          role: { type: "string", description: "Filter by role (admin, user, guest)" },
          active: { type: "boolean", description: "Filter by active status (default true)" },
          limit: { type: "number", description: "Max results (default 50)" },
        },
      },
      execute: async (_toolCallId: string, params: any) => {
        const limit = Math.min(params.limit ?? 50, 200);
        const active = params.active ?? true;
        console.log(`[pi-bridge] users__list: role=${params.role ?? "all"} active=${active}`);
        try {
          let sql = `SELECT u.id, u.username, u.display_name, u.role, u.active, u.created_at,
                       COUNT(ui.id)::int AS identity_count
                     FROM users u
                     LEFT JOIN user_identities ui ON ui.user_id = u.id
                     WHERE u.active = $1`;
          const vals: any[] = [active];
          let idx = 2;

          if (params.role) {
            sql += ` AND u.role = $${idx++}`;
            vals.push(params.role);
          }

          sql += ` GROUP BY u.id ORDER BY u.created_at DESC LIMIT $${idx}`;
          vals.push(limit);

          const result = await q(sql, vals);
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error listing users: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "users__get",
      label: "users/get",
      description: "Get a user by ID or username, including their linked platform identities.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "User ID (UUID)" },
          username: { type: "string", description: "Username" },
        },
      },
      execute: async (_toolCallId: string, params: any) => {
        if (!params.id && !params.username) {
          return {
            content: [{ type: "text" as const, text: "Error: provide either id or username" }],
            details: undefined,
          };
        }
        const field = params.id ? "id" : "username";
        const value = params.id ?? params.username;
        console.log(`[pi-bridge] users__get: ${field}=${value}`);
        try {
          const userResult = await q(
            `SELECT id, username, display_name, role, active, tool_config, config, created_at, modified_at
             FROM users WHERE ${field} = $1`,
            [value]
          );
          if (userResult.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: `User not found: ${field}=${value}` }],
              details: undefined,
            };
          }
          const userRow = userResult.rows[0] as any;
          const idResult = await q(
            `SELECT id, platform, platform_user_id, platform_username, created_at
             FROM user_identities WHERE user_id = $1`,
            [userRow.id]
          );
          const output = { ...userRow, identities: idResult.rows };
          return {
            content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error getting user: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "users__create",
      label: "users/create",
      description: "Create a new user account.",
      parameters: {
        type: "object",
        properties: {
          username: { type: "string", description: "Unique username" },
          display_name: { type: "string", description: "Display name" },
          role: { type: "string", description: "Role: admin, user, or guest (default: user)" },
        },
        required: ["username"],
      },
      execute: async (_toolCallId: string, params: any) => {
        const role = params.role ?? "user";
        console.log(`[pi-bridge] users__create: username=${params.username} role=${role}`);
        try {
          const id = randomUUID();
          const result = await q(
            `INSERT INTO users (id, username, display_name, role)
             VALUES ($1, $2, $3, $4)
             RETURNING id, username, display_name, role`,
            [id, params.username, params.display_name ?? params.username, role]
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows[0], null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error creating user: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "users__update",
      label: "users/update",
      description: "Update user fields. Only provided fields are changed.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "User ID to update" },
          display_name: { type: "string", description: "New display name" },
          role: { type: "string", description: "New role (admin, user, guest)" },
          active: { type: "boolean", description: "Active status" },
          config: { type: "object", description: "User config (prompt_additions, etc.)" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] users__update: ${params.id}`);
        try {
          const sets: string[] = ["modified_at = NOW()"];
          const vals: any[] = [];
          let idx = 1;

          if (params.display_name !== undefined) {
            sets.push(`display_name = $${idx++}`);
            vals.push(params.display_name);
          }
          if (params.role !== undefined) {
            sets.push(`role = $${idx++}`);
            vals.push(params.role);
          }
          if (params.active !== undefined) {
            sets.push(`active = $${idx++}`);
            vals.push(params.active);
          }
          if (params.config !== undefined) {
            sets.push(`config = config || $${idx++}::jsonb`);
            vals.push(JSON.stringify(params.config));
          }
          vals.push(params.id);

          const result = await q(
            `UPDATE users SET ${sets.join(", ")} WHERE id = $${idx}
             RETURNING id, username, display_name, role, active`,
            vals
          );
          if (result.rowCount === 0) {
            return {
              content: [{ type: "text" as const, text: `User not found: ${params.id}` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows[0], null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error updating user: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "users__add_identity",
      label: "users/add_identity",
      description: "Link a platform identity (discord, slack, etc.) to a user.",
      parameters: {
        type: "object",
        properties: {
          user_id: { type: "string", description: "User ID to link identity to" },
          platform: { type: "string", description: "Platform name (e.g. discord, slack, github)" },
          platform_user_id: { type: "string", description: "User's ID on the platform" },
          platform_username: { type: "string", description: "User's display name on the platform (optional)" },
        },
        required: ["user_id", "platform", "platform_user_id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] users__add_identity: user=${params.user_id} platform=${params.platform}`);
        try {
          const id = randomUUID();
          const result = await q(
            `INSERT INTO user_identities (id, user_id, platform, platform_user_id, platform_username)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, user_id, platform, platform_user_id`,
            [id, params.user_id, params.platform, params.platform_user_id, params.platform_username ?? null]
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows[0], null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error adding identity: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "users__remove_identity",
      label: "users/remove_identity",
      description: "Remove a platform identity by its ID.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Identity row ID to remove" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] users__remove_identity: ${params.id}`);
        try {
          const result = await q(
            `DELETE FROM user_identities WHERE id = $1`,
            [params.id]
          );
          if (result.rowCount === 0) {
            return {
              content: [{ type: "text" as const, text: `Identity not found: ${params.id}` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Removed identity ${params.id}` }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error removing identity: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "policy__list_tool_access",
      label: "policy/list_tool_access",
      description: "Show the current tool access policy data (roles, exceptions, user overrides). This is the data JSONB from the 'tool-access' OPA policy.",
      parameters: {
        type: "object",
        properties: {},
      },
      execute: async (_toolCallId: string, _params: any) => {
        console.log(`[pi-bridge] policy__list_tool_access`);
        try {
          const result = await q(
            "SELECT data FROM opa_policies WHERE policy_id = 'tool-access'",
            []
          );
          if (result.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: "No tool-access policy found in opa_policies" }],
              details: undefined,
            };
          }
          const data = (result.rows[0] as any).data;
          const toolAccess = data?.smith?.tool_access ?? data;
          return {
            content: [{ type: "text" as const, text: JSON.stringify(toolAccess, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error reading tool access policy: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "policy__set_tool_access",
      label: "policy/set_tool_access",
      description: "Update tool access rules. Set role exceptions (tools to deny for allow-default roles, or tools to allow for deny-default roles) or per-user overrides. Publishes a policy reload signal so changes take effect on next evaluation.",
      parameters: {
        type: "object",
        properties: {
          role: { type: "string", description: "Role to update (admin, user, guest)" },
          role_default: { type: "string", description: "Set role default to 'allow' or 'deny'" },
          exceptions: { type: "object", description: "Exceptions map: {tool_name: true, ...}. For allow-default roles these are deny-listed tools; for deny-default roles these are allow-listed tools. Replaces existing exceptions for this role." },
          user_id: { type: "string", description: "User ID for per-user override (alternative to role)" },
          user_default: { type: "string", description: "Per-user default: 'allow' or 'deny'" },
          user_tools: { type: "object", description: "Per-user tool overrides: {tool_name: 'allow'|'deny', ...}" },
        },
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] policy__set_tool_access:`, JSON.stringify(params).slice(0, 200));
        try {
          // Read current data
          const current = await q(
            "SELECT data FROM opa_policies WHERE policy_id = 'tool-access'",
            []
          );
          if (current.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: "No tool-access policy found" }],
              details: undefined,
            };
          }
          const data = JSON.parse(JSON.stringify((current.rows[0] as any).data));
          const ta = data.smith.tool_access;

          if (params.role) {
            if (!ta.roles[params.role]) {
              ta.roles[params.role] = { default: "deny", exceptions: {} };
            }
            if (params.role_default) {
              ta.roles[params.role].default = params.role_default;
            }
            if (params.exceptions !== undefined) {
              ta.roles[params.role].exceptions = params.exceptions;
            }
          }

          if (params.user_id) {
            if (!ta.user_overrides[params.user_id]) {
              ta.user_overrides[params.user_id] = {};
            }
            if (params.user_default) {
              ta.user_overrides[params.user_id].default = params.user_default;
            }
            if (params.user_tools !== undefined) {
              ta.user_overrides[params.user_id].tools = {
                ...(ta.user_overrides[params.user_id].tools ?? {}),
                ...params.user_tools,
              };
            }
          }

          await q(
            "UPDATE opa_policies SET data = $1, modified_at = NOW() WHERE policy_id = 'tool-access'",
            [JSON.stringify(data)]
          );

          // Push updated policy data directly to OPA
          try {
            await fetch(`${OPA_URL}/v1/data/smith/tool_access`, {
              method: "PUT",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(ta),
            });
          } catch (pushErr) {
            console.warn("[pi-bridge] Failed to push policy data to OPA:", (pushErr as Error).message);
          }

          return {
            content: [{ type: "text" as const, text: JSON.stringify(ta, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error updating tool access policy: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "policy__remove_tool_access",
      label: "policy/remove_tool_access",
      description: "Remove tool access entries. Remove specific role exceptions, entire user overrides, or specific user tool overrides. Publishes a policy reload signal.",
      parameters: {
        type: "object",
        properties: {
          role: { type: "string", description: "Role whose exceptions to modify" },
          remove_exceptions: { type: "array", description: "List of tool names to remove from role exceptions" },
          user_id: { type: "string", description: "User ID whose override to modify or remove entirely" },
          remove_user_tools: { type: "array", description: "List of tool names to remove from user override" },
          remove_user: { type: "boolean", description: "If true, remove the entire user override entry" },
        },
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] policy__remove_tool_access:`, JSON.stringify(params).slice(0, 200));
        try {
          const current = await q(
            "SELECT data FROM opa_policies WHERE policy_id = 'tool-access'",
            []
          );
          if (current.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: "No tool-access policy found" }],
              details: undefined,
            };
          }
          const data = JSON.parse(JSON.stringify((current.rows[0] as any).data));
          const ta = data.smith.tool_access;

          if (params.role && params.remove_exceptions && ta.roles[params.role]) {
            for (const tool of params.remove_exceptions) {
              delete ta.roles[params.role].exceptions[tool];
            }
          }

          if (params.user_id) {
            if (params.remove_user) {
              delete ta.user_overrides[params.user_id];
            } else if (params.remove_user_tools && ta.user_overrides[params.user_id]?.tools) {
              for (const tool of params.remove_user_tools) {
                delete ta.user_overrides[params.user_id].tools[tool];
              }
            }
          }

          await q(
            "UPDATE opa_policies SET data = $1, modified_at = NOW() WHERE policy_id = 'tool-access'",
            [JSON.stringify(data)]
          );

          // Push updated policy data directly to OPA
          try {
            await fetch(`${OPA_URL}/v1/data/smith/tool_access`, {
              method: "PUT",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(ta),
            });
          } catch (pushErr) {
            console.warn("[pi-bridge] Failed to push policy data to OPA:", (pushErr as Error).message);
          }

          return {
            content: [{ type: "text" as const, text: JSON.stringify(ta, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error removing tool access entries: ${err}` }],
            details: undefined,
          };
        }
      },
    },

    // ── Agent profile management tools ────────────────────────────────

    {
      name: "agents__list",
      label: "agents/list",
      description: "List all agent profiles with their ID, model, trust level, and enabled status.",
      parameters: {
        type: "object",
        properties: {
          enabled: { type: "boolean", description: "Filter by enabled status" },
          trusted: { type: "boolean", description: "Filter by trust level" },
        },
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agents__list`);
        try {
          const conditions: string[] = [];
          const vals: any[] = [];
          if (params.enabled !== undefined) {
            vals.push(params.enabled);
            conditions.push(`enabled = $${vals.length}`);
          }
          if (params.trusted !== undefined) {
            vals.push(params.trusted);
            conditions.push(`trusted = $${vals.length}`);
          }
          const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
          const result = await q(
            `SELECT id, display_name, provider, model_id, thinking_level, tool_policy, trusted, max_turns, enabled, modified_at FROM agents ${where} ORDER BY id`,
            vals
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error listing agents: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "agents__get",
      label: "agents/get",
      description: "Get full details of an agent profile by ID, including system prompt and config.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Agent ID (e.g. 'default', 'untrusted-proxy')" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agents__get: ${params.id}`);
        try {
          const result = await q("SELECT * FROM agents WHERE id = $1", [params.id]);
          if (result.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: `Agent "${params.id}" not found` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows[0], null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error reading agent: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "agents__create",
      label: "agents/create",
      description: "Create a new agent profile. Set trusted=false for untrusted proxy agents (canary verification is automatic).",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Unique agent ID" },
          display_name: { type: "string", description: "Display name" },
          provider: { type: "string", description: "LLM provider (default: anthropic)" },
          model_id: { type: "string", description: "Model ID (default: claude-sonnet-4-5-20250929)" },
          thinking_level: { type: "string", description: "Thinking level (default: off)" },
          system_prompt: { type: "string", description: "Custom system prompt (null = use base)" },
          tool_policy: { type: "string", description: "OPA policy ID for tool access (default: tool-access)" },
          trusted: { type: "boolean", description: "Whether this agent is trusted (default: true). Untrusted agents get canary verification." },
          max_turns: { type: "number", description: "Max conversation turns (null = unlimited)" },
          config: { type: "object", description: "Extra config JSONB" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agents__create: ${params.id}`);
        try {
          const result = await q(
            `INSERT INTO agents (id, display_name, provider, model_id, thinking_level, system_prompt, tool_policy, trusted, max_turns, config)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, display_name, provider, model_id, trusted, enabled`,
            [
              params.id,
              params.display_name ?? "",
              params.provider ?? "anthropic",
              params.model_id ?? "claude-sonnet-4-5-20250929",
              params.thinking_level ?? "off",
              params.system_prompt ?? null,
              params.tool_policy ?? "tool-access",
              params.trusted !== undefined ? params.trusted : true,
              params.max_turns ?? null,
              JSON.stringify(params.config ?? {}),
            ]
          );
          return {
            content: [{ type: "text" as const, text: `Created agent:\n${JSON.stringify(result.rows[0], null, 2)}` }],
            details: undefined,
          };
        } catch (err: any) {
          if (err.code === "23505") {
            return {
              content: [{ type: "text" as const, text: `Error: agent "${params.id}" already exists` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Error creating agent: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "agents__update",
      label: "agents/update",
      description: "Update an agent profile. Changes take effect on the next session using this agent.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Agent ID to update" },
          display_name: { type: "string", description: "New display name" },
          provider: { type: "string", description: "New LLM provider" },
          model_id: { type: "string", description: "New model ID" },
          thinking_level: { type: "string", description: "New thinking level" },
          system_prompt: { type: "string", description: "New system prompt (empty string to clear)" },
          tool_policy: { type: "string", description: "New OPA policy ID" },
          trusted: { type: "boolean", description: "Trust level" },
          max_turns: { type: "number", description: "Max turns (0 to clear)" },
          enabled: { type: "boolean", description: "Enable or disable" },
          config: { type: "object", description: "Config JSONB (merged)" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agents__update: ${params.id}`);
        try {
          const sets: string[] = [];
          const vals: any[] = [];

          if (params.display_name !== undefined) { vals.push(params.display_name); sets.push(`display_name = $${vals.length}`); }
          if (params.provider !== undefined) { vals.push(params.provider); sets.push(`provider = $${vals.length}`); }
          if (params.model_id !== undefined) { vals.push(params.model_id); sets.push(`model_id = $${vals.length}`); }
          if (params.thinking_level !== undefined) { vals.push(params.thinking_level); sets.push(`thinking_level = $${vals.length}`); }
          if (params.system_prompt !== undefined) { vals.push(params.system_prompt || null); sets.push(`system_prompt = $${vals.length}`); }
          if (params.tool_policy !== undefined) { vals.push(params.tool_policy); sets.push(`tool_policy = $${vals.length}`); }
          if (params.trusted !== undefined) { vals.push(params.trusted); sets.push(`trusted = $${vals.length}`); }
          if (params.max_turns !== undefined) { vals.push(params.max_turns || null); sets.push(`max_turns = $${vals.length}`); }
          if (params.enabled !== undefined) { vals.push(params.enabled); sets.push(`enabled = $${vals.length}`); }
          if (params.config !== undefined) { vals.push(JSON.stringify(params.config)); sets.push(`config = config || $${vals.length}::jsonb`); }

          if (sets.length === 0) {
            return { content: [{ type: "text" as const, text: "Error: no fields to update" }], details: undefined };
          }

          sets.push("modified_at = NOW()");
          vals.push(params.id);
          const result = await q(
            `UPDATE agents SET ${sets.join(", ")} WHERE id = $${vals.length} RETURNING *`,
            vals
          );
          if (result.rows.length === 0) {
            return { content: [{ type: "text" as const, text: `Agent "${params.id}" not found` }], details: undefined };
          }
          return {
            content: [{ type: "text" as const, text: `Updated agent:\n${JSON.stringify(result.rows[0], null, 2)}\n\nChanges take effect on the next session.` }],
            details: undefined,
          };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `Error updating agent: ${err}` }], details: undefined };
        }
      },
    },
    {
      name: "agents__delete",
      label: "agents/delete",
      description: "Delete an agent profile. Cannot delete the 'default' agent.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string", description: "Agent ID to delete" },
        },
        required: ["id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] agents__delete: ${params.id}`);
        if (params.id === "default") {
          return { content: [{ type: "text" as const, text: "Error: cannot delete the default agent" }], details: undefined };
        }
        try {
          const result = await q("DELETE FROM agents WHERE id = $1 RETURNING id, display_name", [params.id]);
          if (result.rows.length === 0) {
            return { content: [{ type: "text" as const, text: `Agent "${params.id}" not found` }], details: undefined };
          }
          const row = result.rows[0] as any;
          return { content: [{ type: "text" as const, text: `Deleted agent "${row.display_name}" (${row.id})` }], details: undefined };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `Error deleting agent: ${err}` }], details: undefined };
        }
      },
    },

    // ── Full OPA policy CRUD tools ─────────────────────────────────────

    {
      name: "policy__list_all",
      label: "policy/list_all",
      description: "List all OPA policies with their ID, capability, active status, and priority.",
      parameters: {
        type: "object",
        properties: {
          active: { type: "boolean", description: "Filter by active status" },
          capability: { type: "string", description: "Filter by capability (e.g. 'tool_access', 'envoy_authz')" },
        },
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] policy__list_all`);
        try {
          const conditions: string[] = [];
          const vals: any[] = [];
          if (params.active !== undefined) {
            vals.push(params.active);
            conditions.push(`active = $${vals.length}`);
          }
          if (params.capability !== undefined) {
            vals.push(params.capability);
            conditions.push(`capability = $${vals.length}`);
          }
          const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
          const result = await q(
            `SELECT policy_id, capability, entrypoint, priority, active, version, modified_at FROM opa_policies ${where} ORDER BY priority, policy_id`,
            vals
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error listing policies: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "policy__get",
      label: "policy/get",
      description: "Get a specific OPA policy by ID, including its Rego module source and data.",
      parameters: {
        type: "object",
        properties: {
          policy_id: { type: "string", description: "Policy ID (e.g. 'tool-access', 'envoy-authz')" },
        },
        required: ["policy_id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] policy__get: ${params.policy_id}`);
        try {
          const result = await q(
            "SELECT * FROM opa_policies WHERE policy_id = $1",
            [params.policy_id]
          );
          if (result.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: `Policy "${params.policy_id}" not found` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result.rows[0], null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error reading policy: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "policy__create",
      label: "policy/create",
      description: "Create a new OPA policy. The module is Rego source code, data is optional JSONB for the policy's static data.",
      parameters: {
        type: "object",
        properties: {
          policy_id: { type: "string", description: "Unique policy ID" },
          capability: { type: "string", description: "Capability scope (e.g. 'fs.write.v1', 'tool_access', '*')" },
          entrypoint: { type: "string", description: "Rego entrypoint (e.g. 'data.smith.deny')" },
          module: { type: "string", description: "Rego source code" },
          data: { type: "object", description: "Optional static data JSONB" },
          priority: { type: "number", description: "Priority (lower evaluates first, default 0)" },
          active: { type: "boolean", description: "Whether the policy is active (default true)" },
        },
        required: ["policy_id", "capability", "entrypoint", "module"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] policy__create: ${params.policy_id}`);
        try {
          const result = await q(
            `INSERT INTO opa_policies (policy_id, capability, entrypoint, module, data, priority, active)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING policy_id, capability, entrypoint, priority, active, version`,
            [
              params.policy_id,
              params.capability,
              params.entrypoint,
              params.module,
              params.data ? JSON.stringify(params.data) : null,
              params.priority ?? 0,
              params.active !== undefined ? params.active : true,
            ]
          );

          // Push to OPA
          try {
            await fetch(`${OPA_URL}/v1/policies/${params.policy_id}`, {
              method: "PUT",
              headers: { "content-type": "text/plain" },
              body: params.module,
            });
            if (params.data) {
              await fetch(`${OPA_URL}/v1/data`, {
                method: "PATCH",
                headers: { "content-type": "application/json" },
                body: JSON.stringify([{ op: "add", path: "/", value: params.data }]),
              });
            }
          } catch (pushErr) {
            console.warn("[pi-bridge] Failed to push new policy to OPA:", (pushErr as Error).message);
          }

          return {
            content: [{ type: "text" as const, text: `Created policy:\n${JSON.stringify(result.rows[0], null, 2)}` }],
            details: undefined,
          };
        } catch (err: any) {
          if (err.code === "23505") {
            return {
              content: [{ type: "text" as const, text: `Error: policy "${params.policy_id}" already exists` }],
              details: undefined,
            };
          }
          return {
            content: [{ type: "text" as const, text: `Error creating policy: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "policy__update",
      label: "policy/update",
      description: "Update an existing OPA policy. Can change module, data, priority, active status, or capability.",
      parameters: {
        type: "object",
        properties: {
          policy_id: { type: "string", description: "Policy ID to update" },
          module: { type: "string", description: "New Rego source code" },
          data: { type: "object", description: "New static data JSONB (replaces existing)" },
          capability: { type: "string", description: "New capability scope" },
          entrypoint: { type: "string", description: "New Rego entrypoint" },
          priority: { type: "number", description: "New priority" },
          active: { type: "boolean", description: "Enable or disable the policy" },
        },
        required: ["policy_id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] policy__update: ${params.policy_id}`);
        try {
          const sets: string[] = [];
          const vals: any[] = [];

          if (params.module !== undefined) {
            vals.push(params.module);
            sets.push(`module = $${vals.length}`);
          }
          if (params.data !== undefined) {
            vals.push(JSON.stringify(params.data));
            sets.push(`data = $${vals.length}`);
          }
          if (params.capability !== undefined) {
            vals.push(params.capability);
            sets.push(`capability = $${vals.length}`);
          }
          if (params.entrypoint !== undefined) {
            vals.push(params.entrypoint);
            sets.push(`entrypoint = $${vals.length}`);
          }
          if (params.priority !== undefined) {
            vals.push(params.priority);
            sets.push(`priority = $${vals.length}`);
          }
          if (params.active !== undefined) {
            vals.push(params.active);
            sets.push(`active = $${vals.length}`);
          }

          if (sets.length === 0) {
            return {
              content: [{ type: "text" as const, text: "Error: no fields to update" }],
              details: undefined,
            };
          }

          sets.push("version = version + 1");
          sets.push("modified_at = NOW()");
          vals.push(params.policy_id);
          const result = await q(
            `UPDATE opa_policies SET ${sets.join(", ")} WHERE policy_id = $${vals.length} RETURNING *`,
            vals
          );

          if (result.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: `Policy "${params.policy_id}" not found` }],
              details: undefined,
            };
          }

          // Push to OPA
          const row = result.rows[0] as any;
          try {
            if (params.module !== undefined) {
              await fetch(`${OPA_URL}/v1/policies/${params.policy_id}`, {
                method: "PUT",
                headers: { "content-type": "text/plain" },
                body: row.module,
              });
            }
            if (params.data !== undefined && row.data) {
              // Extract the nested path from the policy data structure
              await fetch(`${OPA_URL}/v1/data`, {
                method: "PATCH",
                headers: { "content-type": "application/json" },
                body: JSON.stringify([{ op: "add", path: "/", value: row.data }]),
              });
            }
          } catch (pushErr) {
            console.warn("[pi-bridge] Failed to push policy update to OPA:", (pushErr as Error).message);
          }

          return {
            content: [{ type: "text" as const, text: JSON.stringify(row, null, 2) }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error updating policy: ${err}` }],
            details: undefined,
          };
        }
      },
    },
    {
      name: "policy__delete",
      label: "policy/delete",
      description: "Delete an OPA policy by ID. Removes from both the database and the live OPA instance.",
      parameters: {
        type: "object",
        properties: {
          policy_id: { type: "string", description: "Policy ID to delete" },
        },
        required: ["policy_id"],
      },
      execute: async (_toolCallId: string, params: any) => {
        console.log(`[pi-bridge] policy__delete: ${params.policy_id}`);
        try {
          const result = await q(
            "DELETE FROM opa_policies WHERE policy_id = $1 RETURNING policy_id, capability",
            [params.policy_id]
          );
          if (result.rows.length === 0) {
            return {
              content: [{ type: "text" as const, text: `Policy "${params.policy_id}" not found` }],
              details: undefined,
            };
          }

          // Remove from OPA
          try {
            await fetch(`${OPA_URL}/v1/policies/${params.policy_id}`, { method: "DELETE" });
          } catch (pushErr) {
            console.warn("[pi-bridge] Failed to delete policy from OPA:", (pushErr as Error).message);
          }

          const row = result.rows[0] as any;
          return {
            content: [{ type: "text" as const, text: `Deleted policy "${row.policy_id}" (capability: ${row.capability})` }],
            details: undefined,
          };
        } catch (err) {
          return {
            content: [{ type: "text" as const, text: `Error deleting policy: ${err}` }],
            details: undefined,
          };
        }
      },
    },
  ];
}

// ── Thread History ────────────────────────────────────────────────────

import type { UserMessage, AssistantMessage } from "@mariozechner/pi-ai";
import type { AppMessage } from "@mariozechner/pi-agent";

function buildHistoryMessages(history: ThreadHistoryMessage[]): AppMessage[] {
  return history.map((msg): AppMessage => {
    const ts = msg.timestamp
      ? new Date(msg.timestamp).getTime()
      : Date.now();

    if (msg.role === "assistant") {
      return {
        role: "assistant",
        content: [{ type: "text", text: msg.content }],
        api: "messages" as any,
        provider: PROVIDER,
        model: MODEL_ID,
        usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 } as any,
        stopReason: "stop",
        timestamp: ts,
      } satisfies AssistantMessage;
    }

    // User message — prefix with username if available
    const content = msg.username
      ? `**${msg.username}:** ${msg.content}`
      : msg.content;

    return {
      role: "user",
      content,
      timestamp: ts,
    } satisfies UserMessage;
  });
}

// ── Main ──────────────────────────────────────────────────────────────
const sessions = new Map<string, AgentSession>();

async function main() {
  console.log(`[pi-bridge] Connecting to NATS at ${NATS_URL}`);
  const nc = await connect({ servers: NATS_URL });
  console.log(`[pi-bridge] Connected to NATS`);
  console.log(`[pi-bridge] Using model: ${PROVIDER}/${MODEL_ID}`);
  console.log(`[pi-bridge] MCP index: ${MCP_INDEX_URL}`);
  console.log(`[pi-bridge] agentd URL: ${AGENTD_URL}`);

  // Startup probe: check MCP tools availability
  const mcpTools = await fetchMcpTools();
  const serverCounts: Record<string, number> = {};
  for (const t of mcpTools) {
    serverCounts[t.server] = (serverCounts[t.server] ?? 0) + 1;
  }
  console.log(`[pi-bridge] MCP tools available: ${mcpTools.length}`, serverCounts);

  // Startup probe: check agentd availability
  const agentdCaps = await fetchAgentdCapabilities();
  console.log(`[pi-bridge] agentd capabilities available: ${agentdCaps.length} + 3 file tools`);
  if (agentdCaps.length > 0) {
    console.log(`[pi-bridge] agentd caps: ${agentdCaps.map(c => c.name).join(", ")}`);
  }

  const sub = nc.subscribe(SESSION_START_SUBJECT);
  console.log(`[pi-bridge] Listening on ${SESSION_START_SUBJECT}`);

  const cleanupTimer = setInterval(() => {
    cleanupIdleSessions(nc).catch((err) => {
      console.error("[pi-bridge] Idle cleanup error:", err);
    });
  }, PI_SESSION_CLEANUP_INTERVAL_MS);

  for await (const msg of sub) {
    try {
      const request: SessionStartRequest = JSON.parse(sc.decode(msg.data));
      const response = await handleSessionStart(nc, request);
      if (msg.reply) {
        msg.respond(sc.encode(JSON.stringify(response)));
      }
    } catch (err) {
      console.error(`[pi-bridge] Error handling session start:`, err);
      if (msg.reply) {
        msg.respond(
          sc.encode(JSON.stringify({ error: String(err) }))
        );
      }
    }
  }

  clearInterval(cleanupTimer);
}

async function handleSessionStart(
  nc: NatsConnection,
  request: SessionStartRequest
): Promise<SessionStartResponse> {
  const sessionId = randomUUID();
  const requestId = randomUUID();
  const traceId = randomUUID();
  const steeringSubject = `smith.sessions.${sessionId}.steering`;
  const responseSubject = `smith.sessions.${sessionId}.response`;

  // Resolve user from platform identity (server-side, tamper-proof)
  const user = await resolveUser(request.metadata);
  if (user) {
    console.log(`[pi-bridge] New session ${sessionId} user=${user.username} role=${user.role} goal="${request.goal.slice(0, 80)}"`);
  } else {
    console.warn(`[pi-bridge] New session ${sessionId} UNKNOWN user (source=${request.metadata?.source}, sender=${request.metadata?.sender_id}) goal="${request.goal.slice(0, 80)}"`);
  }
  const effectiveUser = user ?? GUEST_USER;

  // Resolve agent profile: request.metadata.agent_id > AGENT_ID env var > 'default'
  const requestedAgentId = (request.metadata?.agent_id as string) ?? AGENT_ID ?? "default";
  const agentProfile = await loadAgentProfile(requestedAgentId);
  const effectiveProfile = applyUserOverrides(agentProfile, effectiveUser);
  console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] Agent: ${effectiveProfile.id} (${effectiveProfile.display_name}) trusted=${effectiveProfile.trusted}`);

  // Generate canary for untrusted agents
  const canary = !effectiveProfile.trusted ? generateCanary() : null;
  if (canary) {
    console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] Canary injected for untrusted agent`);
  }

  // Root span for the entire chat session lifecycle
  const sessionSpan = tracer.startSpan("chat.session", {
    attributes: {
      "session.id": sessionId,
      "agent.id": effectiveProfile.id,
      "agent.trusted": effectiveProfile.trusted,
      "chat.source": (request.metadata?.source as string) ?? "unknown",
      "chat.channel_id": (request.metadata?.channel_id as string) ?? "",
      "user.id": effectiveUser.id || "unknown",
      "user.role": effectiveUser.role,
    },
  });

  // Emit session telemetry (consumed by session-recorder)
  nc.publish(
    `smith.telemetry.session.created`,
    sc.encode(JSON.stringify({
      session_id: sessionId,
      goal: request.goal,
      metadata: { ...request.metadata, agent_id: effectiveProfile.id, user_id: effectiveUser.id || null },
      timestamp: new Date().toISOString(),
    }))
  );

  // Create a per-session agentd sandbox
  const sandboxId = await createAgentdSandbox();
  const sessionAgentdRef: AgentdRef = { sandboxId, pendingAttachments: [] };
  if (sandboxId) {
    console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] Created agentd sandbox: ${sandboxId}`);
  }

  // Build session-scoped tools with this sandbox reference
  const agentdCaps = await fetchAgentdCapabilities();
  const sessionCapTools = buildAgentdCapabilityTools(agentdCaps, sessionAgentdRef);
  const sessionFileTools = buildAgentdFileTools(sessionAgentdRef);
  const mcpTools = await fetchMcpTools();
  const sessionMcpTools = buildAgentTools(mcpTools);
  const sessionNoteTools = buildNoteTools(effectiveUser);
  const sessionUserMgmtTools = buildUserManagementTools(effectiveUser);
  const allTools = [...sessionMcpTools, ...sessionCapTools, ...sessionFileTools, ...sessionNoteTools, ...sessionUserMgmtTools];
  const toolAccessCtx: ToolAccessContext = {
    user_id: effectiveUser.id,
    username: effectiveUser.username,
    role: effectiveUser.role,
    agent_id: effectiveProfile.id,
    source: (request.metadata?.source as string) ?? "unknown",
    channel_id: (request.metadata?.channel_id as string) ?? "",
    thread_id: (request.metadata?.thread_id as string) ?? "",
    trigger: (request.metadata?.trigger as string) ?? "chat",
    metadata: { ...request.metadata ?? {}, trusted: effectiveProfile.trusted },
  };
  const sessionTools = await evaluateToolAccess(toolAccessCtx, allTools);

  console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] Tools: ${sessionTools.length}/${allTools.length} (role=${effectiveUser.role})`);

  // Build system prompt: agent profile > base prompt, with platform + tool context
  let systemPrompt = buildSystemPrompt(effectiveProfile, effectiveUser, {
    metadata: request.metadata as Record<string, unknown> | undefined,
    mcpTools,
    agentdCaps,
  });
  if (canary) {
    systemPrompt = injectCanary(systemPrompt, canary.codeword);
  }

  // Resolve LLM config from agent profile (user overrides already applied)
  console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] LLM: ${effectiveProfile.provider}/${effectiveProfile.model_id} thinking=${effectiveProfile.thinking_level}`);

  const bootstrapHistory = buildHistoryMessages(request.thread_history ?? []);
  if (bootstrapHistory.length > 0) {
    console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] Bootstrapped ${bootstrapHistory.length} history messages`);
  }

  // Create pi-agent with direct provider transport
  const baseModel = getModel(effectiveProfile.provider as any, effectiveProfile.model_id as any);
  // Override baseUrl if ANTHROPIC_BASE_URL is set (e.g. for z.ai proxy)
  const model = process.env.ANTHROPIC_BASE_URL
    ? { ...baseModel, baseUrl: process.env.ANTHROPIC_BASE_URL }
    : baseModel;
  const transport = new ProviderTransport({
    getApiKey: (provider: string) => getEnvApiKey(provider as any) ?? process.env.ANTHROPIC_API_KEY,
  });
  const agent = new Agent({
    transport,
    queueMode: "one-at-a-time",
    initialState: {
      systemPrompt,
      model,
      tools: sessionTools,
      messages: bootstrapHistory,
      thinkingLevel: effectiveProfile.thinking_level as any,
      ...(effectiveProfile.max_turns != null ? { maxTurns: effectiveProfile.max_turns } : {}),
    },
  });

  // Thread history is query-driven: the agent uses postgres__query and discord tools
  // to fetch conversation context when needed, rather than pre-injection.

  // Publish the initial goal as a steering message so session-recorder captures it
  // (published before subscribing so pi-bridge doesn't consume its own message)
  nc.publish(
    steeringSubject,
    sc.encode(JSON.stringify({ role: "user", content: request.goal }))
  );

  // Subscribe to steering subject for follow-up messages (after initial publish)
  const steeringSub = nc.subscribe(steeringSubject);

  const session: AgentSession = {
    agent,
    steeringSub,
    responseSubject,
    agentd: sessionAgentdRef,
    canaryExpected: canary?.expected ?? null,
    sessionSpan,
    turnCount: 0,
    user: effectiveUser,
    lastActiveAt: Date.now(),
  };
  sessions.set(sessionId, session);

  // Handle the initial goal as the first prompt
  runAgentPrompt(nc, sessionId, request.goal);

  // Handle follow-up steering messages in background
  handleSteering(nc, sessionId);

  return {
    request_id: requestId,
    session_id: sessionId,
    steering_subject: steeringSubject,
    trace_id: traceId,
    response_subject: responseSubject,
  };
}

// ── /smith Command System ─────────────────────────────────────────────

interface CommandResult {
  handled: boolean;
  response?: string;
}

const SMITH_CMD_PREFIX = "/smith";

const MODEL_ALIASES: Record<string, [string, string]> = {
  "opus":    ["anthropic", "claude-opus-4-6"],
  "sonnet":  ["anthropic", "claude-sonnet-4-5-20250929"],
  "haiku":   ["anthropic", "claude-haiku-4-5-20251001"],
};

function cmdHelp(): CommandResult {
  const help = [
    "**Smith Commands**",
    "",
    "| Command | Description |",
    "|---------|-------------|",
    "| `/smith help` | Show this help |",
    "| `/smith status` | Session info: model, thinking, tools, turns |",
    "| `/smith model [id]` | Show or switch model (aliases: opus, sonnet, haiku) |",
    "| `/smith thinking [level]` | Show or set thinking (off, low, medium, high) |",
    "| `/smith clear` | Clear conversation history |",
    "| `/smith tools [query]` | List tools or search by keyword |",
    "| `/smith tool <name> <json>` | Invoke a tool directly, bypass LLM |",
    "| `/smith prompt [text]` | Show or append to system prompt |",
    "| `/smith abort` | Cancel in-flight LLM request |",
  ].join("\n");
  return { handled: true, response: help };
}

function cmdStatus(session: AgentSession): CommandResult {
  const { agent } = session;
  const s = agent.state;
  const model = s.model;
  const lines = [
    "**Session Status**",
    `  Model: \`${model.provider}/${model.id}\``,
    `  Thinking: \`${s.thinkingLevel}\``,
    `  Tools: ${s.tools.length} available`,
    `  Messages: ${s.messages.length}`,
    `  Turns: ${session.turnCount}`,
    `  Streaming: ${s.isStreaming}`,
  ];
  return { handled: true, response: lines.join("\n") };
}

function cmdModel(session: AgentSession, arg: string): CommandResult {
  const { agent } = session;
  if (!arg) {
    const m = agent.state.model;
    return { handled: true, response: `**Current model**: \`${m.provider}/${m.id}\`` };
  }

  const alias = MODEL_ALIASES[arg.toLowerCase()];
  let provider: string;
  let modelId: string;

  if (alias) {
    [provider, modelId] = alias;
  } else if (arg.includes("/")) {
    [provider, modelId] = arg.split("/", 2);
  } else {
    // Assume current provider with the given model ID
    provider = agent.state.model.provider;
    modelId = arg;
  }

  try {
    const newModel = getModel(provider as any, modelId as any);
    const model = process.env.ANTHROPIC_BASE_URL
      ? { ...newModel, baseUrl: process.env.ANTHROPIC_BASE_URL }
      : newModel;
    agent.setModel(model);
    return { handled: true, response: `Model switched to \`${provider}/${modelId}\`` };
  } catch (err) {
    return { handled: true, response: `Failed to set model: ${err}` };
  }
}

function cmdThinking(session: AgentSession, arg: string): CommandResult {
  const { agent } = session;
  if (!arg) {
    return { handled: true, response: `**Thinking level**: \`${agent.state.thinkingLevel}\`` };
  }

  // Map "off" to the actual enum value; pi-agent uses "off" in its ThinkingLevel but pi-ai doesn't
  // The agent's ThinkingLevel type is "off" | "minimal" | "low" | "medium" | "high"
  const valid = ["off", "minimal", "low", "medium", "high"];
  const level = arg.toLowerCase();
  if (!valid.includes(level)) {
    return { handled: true, response: `Invalid thinking level: \`${arg}\`. Valid: ${valid.map(v => `\`${v}\``).join(", ")}` };
  }
  agent.setThinkingLevel(level as any);
  return { handled: true, response: `Thinking level set to \`${level}\`` };
}

function cmdClear(session: AgentSession): CommandResult {
  session.agent.clearMessages();
  return { handled: true, response: "Conversation history cleared." };
}

function cmdTools(session: AgentSession, query: string): CommandResult {
  const tools = session.agent.state.tools;
  if (!query) {
    // Group by server prefix
    const groups: Record<string, string[]> = {};
    for (const t of tools) {
      const parts = t.name.split("__");
      const server = parts.length > 1 ? parts[0] : "(host)";
      if (!groups[server]) groups[server] = [];
      groups[server].push(t.name);
    }
    const lines = [`**Tools** (${tools.length} total)`, ""];
    for (const [server, names] of Object.entries(groups).sort()) {
      lines.push(`**${server}**: ${names.length} tools`);
    }
    return { handled: true, response: lines.join("\n") };
  }

  // Search by keyword
  const q = query.toLowerCase();
  const matches = tools.filter(
    (t) => t.name.toLowerCase().includes(q) || (t.description ?? "").toLowerCase().includes(q),
  );
  if (matches.length === 0) {
    return { handled: true, response: `No tools matching \`${query}\`` };
  }
  const lines = [`**Tools matching** \`${query}\` (${matches.length})`, ""];
  for (const t of matches.slice(0, 30)) {
    lines.push(`- \`${t.name}\`: ${t.description?.slice(0, 100) ?? "(no description)"}`);
  }
  if (matches.length > 30) {
    lines.push(`\n...and ${matches.length - 30} more`);
  }
  return { handled: true, response: lines.join("\n") };
}

async function cmdTool(session: AgentSession, args: string[]): Promise<CommandResult> {
  if (args.length === 0) {
    return { handled: true, response: "Usage: `/smith tool <name> [json_params]`" };
  }

  const toolName = args[0];
  const jsonStr = args.slice(1).join(" ") || "{}";

  const tool = session.agent.state.tools.find((t) => t.name === toolName);
  if (!tool) {
    return { handled: true, response: `Tool not found: \`${toolName}\`` };
  }

  let params: Record<string, any>;
  try {
    params = JSON.parse(jsonStr);
  } catch {
    return { handled: true, response: `Invalid JSON params: \`${jsonStr}\`` };
  }

  try {
    const result = await tool.execute(`cmd-${Date.now()}`, params);
    const text = result.content
      .filter((c): c is { type: "text"; text: string } => c.type === "text")
      .map((c) => c.text)
      .join("\n");
    const truncated = text.length > 1800 ? text.slice(0, 1800) + "\n...(truncated)" : text;
    return { handled: true, response: `**\`${toolName}\` result:**\n${truncated}` };
  } catch (err) {
    return { handled: true, response: `Tool execution error: ${err}` };
  }
}

function cmdPrompt(session: AgentSession, text: string): CommandResult {
  const { agent } = session;
  if (!text) {
    const current = agent.state.systemPrompt;
    const preview = current.length > 500 ? current.slice(0, 500) + "\n...(truncated)" : current;
    return { handled: true, response: `**System prompt** (${current.length} chars):\n\`\`\`\n${preview}\n\`\`\`` };
  }

  const current = agent.state.systemPrompt;
  agent.setSystemPrompt(current + "\n\n" + text);
  return { handled: true, response: `Appended to system prompt (now ${agent.state.systemPrompt.length} chars).` };
}

function cmdAbort(session: AgentSession): CommandResult {
  session.agent.abort();
  return { handled: true, response: "Abort signal sent." };
}

async function handleSmithCommand(
  session: AgentSession,
  input: string,
): Promise<CommandResult> {
  if (!input.startsWith(SMITH_CMD_PREFIX)) {
    return { handled: false };
  }

  const rest = input.slice(SMITH_CMD_PREFIX.length).trim();
  const [subcommand, ...args] = rest.split(/\s+/);
  const argStr = args.join(" ");

  switch (subcommand?.toLowerCase() ?? "help") {
    case "":
    case "help":     return cmdHelp();
    case "status":   return cmdStatus(session);
    case "model":    return cmdModel(session, argStr);
    case "thinking": return cmdThinking(session, argStr);
    case "clear":    return cmdClear(session);
    case "tools":    return cmdTools(session, argStr);
    case "tool":     return cmdTool(session, args);
    case "prompt":   return cmdPrompt(session, argStr);
    case "abort":    return cmdAbort(session);
    default:
      return { handled: true, response: `Unknown command: \`${subcommand}\`. Use \`/smith help\` for available commands.` };
  }
}

async function runAgentPrompt(
  nc: NatsConnection,
  sessionId: string,
  prompt: string
) {
  const session = sessions.get(sessionId);
  if (!session) return;
  session.lastActiveAt = Date.now();

  // Intercept /smith commands before sending to LLM
  const cmdResult = await handleSmithCommand(session, prompt);
  if (cmdResult.handled) {
    nc.publish(
      session.responseSubject,
      sc.encode(JSON.stringify({
        type: "message",
        content: cmdResult.response ?? "(done)",
        done: true,
      }))
    );
    return;
  }

  const { agent, responseSubject, sessionSpan, agentd, canaryExpected } = session;
  const turnIndex = session.turnCount++;

  // Clear attachment accumulator for this turn
  agentd.pendingAttachments.length = 0;

  // chat.turn span — each user→assistant cycle
  const turnSpan = tracer.startSpan("chat.turn", {
    attributes: {
      "session.id": sessionId,
      "turn.index": turnIndex,
      "user.message": prompt.slice(0, 500),
    },
  }, trace.setSpan(context.active(), sessionSpan));

  console.log(
    `[pi-bridge] [${sessionId.slice(0, 8)}] Prompting: "${prompt.slice(0, 120)}"`
  );

  // Collect the full response from agent events
  let fullResponse = "";

  // Track active tool spans
  const toolSpans = new Map<string, { span: Span; startTime: number }>();

  const unsub = agent.subscribe((event) => {
    if (event.type === "message_update") {
      const msg = event.message;
      if (msg && "content" in msg && Array.isArray(msg.content)) {
        const textParts = msg.content
          .filter((c: any) => c.type === "text")
          .map((c: any) => c.text);
        fullResponse = textParts.join("");
      }
    } else if (event.type === "tool_execution_start") {
      console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] Tool: ${event.toolName}`);
      const toolSpan = tracer.startSpan("chat.tool_execution", {
        attributes: {
          "tool.name": event.toolName,
          "tool.server": event.toolName.includes("__") ? event.toolName.split("__")[0] : "unknown",
          "session.id": sessionId,
        },
      }, trace.setSpan(context.active(), turnSpan));
      toolSpans.set(event.toolName, { span: toolSpan, startTime: Date.now() });
    } else if (event.type === "tool_execution_end") {
      console.log(`[pi-bridge] [${sessionId.slice(0, 8)}] Tool done: ${event.toolName} (error=${event.isError})`);
      const tracked = toolSpans.get(event.toolName);
      if (tracked) {
        tracked.span.setAttribute("tool.duration_ms", Date.now() - tracked.startTime);
        if (event.isError) {
          tracked.span.setStatus({ code: SpanStatusCode.ERROR });
        }
        tracked.span.end();
        toolSpans.delete(event.toolName);
      }
    }
  });

  try {
    // chat.llm_call span — wraps the agent.prompt() LLM invocation
    const llmSpan = tracer.startSpan("chat.llm_call", {
      attributes: {
        "llm.model": `${PROVIDER}/${MODEL_ID}`,
        "session.id": sessionId,
      },
    }, trace.setSpan(context.active(), turnSpan));

    await agent.prompt(prompt);

    // Extract token usage from the last assistant message
    const messages = agent.state.messages;
    const lastMsg = messages[messages.length - 1];
    if (lastMsg && "usage" in lastMsg) {
      const usage = (lastMsg as any).usage;
      llmSpan.setAttributes({
        "llm.tokens.input": usage?.inputTokens ?? 0,
        "llm.tokens.output": usage?.outputTokens ?? 0,
        "llm.tokens.cache_read": usage?.cacheReadInputTokens ?? 0,
        "llm.tokens.cache_write": usage?.cacheCreationInputTokens ?? 0,
      });

      // Publish token usage to NATS for session-recorder → PostgreSQL
      const costUsd = typeof usage?.costUSD === "number" ? usage.costUSD : 0;
      nc.publish(
        "smith.telemetry.session.tokens",
        sc.encode(JSON.stringify({
          session_id: sessionId,
          agent_id: AGENT_ID,
          user_id: session.user.id || null,
          turn_index: turnIndex,
          model: `${PROVIDER}/${MODEL_ID}`,
          input_tokens: usage?.inputTokens ?? 0,
          output_tokens: usage?.outputTokens ?? 0,
          cache_read_tokens: usage?.cacheReadInputTokens ?? 0,
          cache_write_tokens: usage?.cacheCreationInputTokens ?? 0,
          cost_usd: costUsd,
        }))
      );

      llmSpan.setAttribute("llm.cost_usd", costUsd);
    }

    llmSpan.end();

    // If we didn't capture streaming content, check final messages
    if (!fullResponse) {
      if (lastMsg && "content" in lastMsg) {
        if (typeof lastMsg.content === "string") {
          fullResponse = lastMsg.content;
        } else if (Array.isArray(lastMsg.content)) {
          fullResponse = lastMsg.content
            .filter((c: any) => c.type === "text")
            .map((c: any) => c.text)
            .join("");
        }
      }
      if (!fullResponse && lastMsg && "errorMessage" in lastMsg && lastMsg.errorMessage) {
        console.error(`[pi-bridge] [${sessionId.slice(0, 8)}] API error: ${lastMsg.errorMessage}`);
        fullResponse = `(error: ${lastMsg.errorMessage})`;
      }
    }

    // Drain any image attachments accumulated during this turn
    const turnAttachments = agentd.pendingAttachments.splice(0);

    if (canaryExpected) {
      const verification = verifyCanary(fullResponse || "", canaryExpected);
      if (!verification.clean) {
        console.warn(`[pi-bridge] [${sessionId.slice(0, 8)}] Canary verification failed for untrusted agent response`);
        turnSpan.setStatus({
          code: SpanStatusCode.ERROR,
          message: "canary_verification_failed",
        });
        fullResponse = "Response blocked: integrity verification failed for untrusted agent output.";
      } else {
        fullResponse = verification.stripped;
      }
    }

    console.log(
      `[pi-bridge] [${sessionId.slice(0, 8)}] Response: ${fullResponse.length} chars, ${turnAttachments.length} attachments`
    );

    nc.publish(
      responseSubject,
      sc.encode(
        JSON.stringify({
          type: "message",
          content: fullResponse || "(no response)",
          done: true,
          ...(turnAttachments.length > 0 ? { attachments: turnAttachments } : {}),
        })
      )
    );

    turnSpan.end();
  } catch (err) {
    console.error(
      `[pi-bridge] [${sessionId.slice(0, 8)}] Agent error:`,
      err
    );
    turnSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
    turnSpan.end();
    nc.publish(
      responseSubject,
      sc.encode(
        JSON.stringify({
          type: "error",
          content: String(err),
        })
      )
    );
  } finally {
    // End any leaked tool spans
    for (const [, tracked] of toolSpans) {
      tracked.span.end();
    }
    toolSpans.clear();
    unsub();
  }
}

async function handleSteering(nc: NatsConnection, sessionId: string) {
  const session = sessions.get(sessionId);
  if (!session) return;

  for await (const msg of session.steeringSub) {
    try {
      session.lastActiveAt = Date.now();
      // Immediately ack so the daemon knows this session is alive
      if (msg.reply) {
        msg.respond(sc.encode(JSON.stringify({ status: "ack", session_id: sessionId })));
      }

      const steering: SteeringMessage = JSON.parse(sc.decode(msg.data));
      if (steering.role === "user" && steering.content) {
        await runAgentPrompt(nc, sessionId, steering.content);
      }
    } catch (err) {
      console.error(
        `[pi-bridge] [${sessionId.slice(0, 8)}] Steering error:`,
        err
      );
    }
  }
}

function closeSession(
  nc: NatsConnection,
  sessionId: string,
  reason: string,
  idleMs?: number,
) {
  const session = sessions.get(sessionId);
  if (!session) return;

  try {
    session.agent.abort();
  } catch {}
  try {
    session.steeringSub.unsubscribe();
  } catch {}
  try {
    session.sessionSpan.end();
  } catch {}
  sessions.delete(sessionId);

  nc.publish(
    "smith.telemetry.session.closed",
    sc.encode(JSON.stringify({
      session_id: sessionId,
      reason,
      idle_ms: idleMs ?? 0,
      timestamp: new Date().toISOString(),
    })),
  );
}

async function cleanupIdleSessions(nc: NatsConnection) {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (session.agent.state.isStreaming) continue;
    const idleMs = now - session.lastActiveAt;
    if (idleMs < PI_SESSION_IDLE_TTL_MS) continue;

    console.log(
      `[pi-bridge] [${sessionId.slice(0, 8)}] Expiring idle session after ${Math.round(idleMs / 1000)}s`,
    );
    closeSession(nc, sessionId, "idle_timeout", idleMs);
  }
}

// ── Start ─────────────────────────────────────────────────────────────
main().catch((err) => {
  console.error("[pi-bridge] Fatal:", err);
  process.exit(1);
});
