#!/usr/bin/env node
/**
 * session-recorder: NATS subscriber that records pi-bridge chat sessions to PostgreSQL.
 *
 * Captures conversation data from the NATS telemetry/message flow:
 *   - smith.telemetry.session.created  → session creation (emitted by pi-bridge)
 *   - smith.sessions.*.steering        → follow-up user messages
 *   - smith.sessions.*.response        → assistant responses
 *
 * Writes to chat_sessions / chat_messages tables. Runs as a sidecar — completely
 * decoupled from the client.
 *
 * Env:
 *   NATS_URL            (default: nats://127.0.0.1:7222)
 *   SESSION_RECORDER_PG (default: postgresql://smith:smith-dev@postgres:5432/smith)
 */

import { connect, StringCodec } from "nats";
import pg from "pg";

const NATS_URL = process.env.NATS_URL ?? "nats://127.0.0.1:7222";
const PG_URL =
  process.env.SESSION_RECORDER_PG ??
  "postgresql://smith:smith-dev@postgres:5432/smith";

const sc = StringCodec();
const pool = new pg.Pool({ connectionString: PG_URL, max: 3 });

// ── DB helpers (best-effort, never throw) ────────────────────────────

async function createSession(sessionId, goal, metadata) {
  try {
    await pool.query(
      `INSERT INTO chat_sessions (id, agent_id, user_id, source, channel_id, thread_id, first_message)
       VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
      [
        sessionId,
        metadata?.agent_id ?? "default",
        metadata?.user_id ?? null,
        metadata?.source ?? "unknown",
        metadata?.channel_id ?? null,
        metadata?.thread_id ?? null,
        (goal ?? "").slice(0, 200),
      ]
    );
  } catch (err) {
    console.error(`[session-recorder] create session failed:`, err.message);
  }
}

// In-memory caches: sessionId → agent_id / user_id (populated from session.created events)
const sessionAgentMap = new Map();
const sessionUserMap = new Map();

async function appendMessage(sessionId, role, content) {
  try {
    const agentId = sessionAgentMap.get(sessionId) ?? "default";
    const userId = sessionUserMap.get(sessionId) ?? null;
    // Ensure session exists (in case telemetry event was missed)
    await pool.query(
      `INSERT INTO chat_sessions (id, agent_id, user_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
      [sessionId, agentId, userId]
    );
    await pool.query(
      `INSERT INTO chat_messages (session_id, agent_id, user_id, role, content) VALUES ($1, $2, $3, $4, $5)`,
      [sessionId, agentId, userId, role, content ?? ""]
    );
    await pool.query(
      `UPDATE chat_sessions SET modified_at = NOW(), message_count = message_count + 1 WHERE id = $1`,
      [sessionId]
    );
  } catch (err) {
    console.error(`[session-recorder] append message failed:`, err.message);
  }
}

// ── Token usage recording ────────────────────────────────────────────

async function recordTokenUsage(data) {
  try {
    await pool.query(
      `INSERT INTO chat_token_usage
         (session_id, agent_id, user_id, turn_index, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        data.session_id,
        data.agent_id ?? "default",
        data.user_id ?? null,
        data.turn_index ?? 0,
        data.model ?? "",
        data.input_tokens ?? 0,
        data.output_tokens ?? 0,
        data.cache_read_tokens ?? 0,
        data.cache_write_tokens ?? 0,
        data.cost_usd ?? 0,
      ]
    );
  } catch (err) {
    console.error(`[session-recorder] record token usage failed:`, err.message);
  }
}

// ── Main ─────────────────────────────────────────────────────────────

async function main() {
  console.log(`[session-recorder] Connecting to NATS at ${NATS_URL}`);
  const nc = await connect({ servers: NATS_URL });
  console.log(`[session-recorder] Connected`);

  // Verify PG connection
  try {
    await pool.query("SELECT 1");
    console.log(`[session-recorder] PostgreSQL connected`);
  } catch (err) {
    console.error(`[session-recorder] PostgreSQL failed:`, err.message);
  }

  // 1. Session created telemetry (emitted by pi-bridge)
  const createdSub = nc.subscribe("smith.telemetry.session.created");
  console.log(`[session-recorder] Listening: smith.telemetry.session.created`);

  // 2. Steering (follow-up user messages)
  const steeringSub = nc.subscribe("smith.sessions.*.steering");
  console.log(`[session-recorder] Listening: smith.sessions.*.steering`);

  // 3. Responses (assistant replies)
  const responseSub = nc.subscribe("smith.sessions.*.response");
  console.log(`[session-recorder] Listening: smith.sessions.*.response`);

  // 4. Token usage telemetry (emitted by pi-bridge after each LLM call)
  const tokenSub = nc.subscribe("smith.telemetry.session.tokens");
  console.log(`[session-recorder] Listening: smith.telemetry.session.tokens`);

  // Process session created events (session row only — user messages come via steering)
  (async () => {
    for await (const msg of createdSub) {
      try {
        const data = JSON.parse(sc.decode(msg.data));
        console.log(
          `[session-recorder] Session created: ${data.session_id?.slice(0, 8)} goal="${(data.goal ?? "").slice(0, 60)}"`
        );
        await createSession(data.session_id, data.goal, data.metadata);
        if (data.metadata?.agent_id) {
          sessionAgentMap.set(data.session_id, data.metadata.agent_id);
        }
        if (data.metadata?.user_id) {
          sessionUserMap.set(data.session_id, data.metadata.user_id);
        }
      } catch (err) {
        console.error(`[session-recorder] Error on session.created:`, err.message);
      }
    }
  })();

  // Process steering (follow-up user messages)
  (async () => {
    for await (const msg of steeringSub) {
      try {
        const sessionId = msg.subject.split(".")[2];
        const data = JSON.parse(sc.decode(msg.data));
        if (data.role === "user" && data.content) {
          console.log(
            `[session-recorder] [${sessionId.slice(0, 8)}] User: "${data.content.slice(0, 60)}"`
          );
          await appendMessage(sessionId, "user", data.content);
        }
      } catch (err) {
        console.error(`[session-recorder] Error on steering:`, err.message);
      }
    }
  })();

  // Process responses (assistant messages)
  (async () => {
    for await (const msg of responseSub) {
      try {
        const sessionId = msg.subject.split(".")[2];
        const data = JSON.parse(sc.decode(msg.data));
        if (data.type === "message" && data.content) {
          console.log(
            `[session-recorder] [${sessionId.slice(0, 8)}] Assistant: ${data.content.length} chars`
          );
          await appendMessage(sessionId, "assistant", data.content);
        } else if (data.type === "error") {
          await appendMessage(sessionId, "error", data.content ?? "unknown error");
        }
      } catch (err) {
        console.error(`[session-recorder] Error on response:`, err.message);
      }
    }
  })();

  // Process token usage events
  (async () => {
    for await (const msg of tokenSub) {
      try {
        const data = JSON.parse(sc.decode(msg.data));
        console.log(
          `[session-recorder] [${(data.session_id ?? "").slice(0, 8)}] Tokens: in=${data.input_tokens} out=${data.output_tokens} cost=$${data.cost_usd ?? 0}`
        );
        await recordTokenUsage(data);
      } catch (err) {
        console.error(`[session-recorder] Error on session.tokens:`, err.message);
      }
    }
  })();

  console.log(`[session-recorder] Running`);
  await nc.closed();
}

main().catch((err) => {
  console.error("[session-recorder] Fatal:", err);
  process.exit(1);
});
