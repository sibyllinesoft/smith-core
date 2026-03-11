#!/usr/bin/env node

import { existsSync } from "fs";
import { join } from "path";
import { findSmithRoot, readSmithConfig, parseEnvFile } from "./lib.js";
import { runInstallerCli } from "./cli.js";

function resolveSmithRoot(): string {
  const config = readSmithConfig();
  if (config && existsSync(config.installPath)) {
    return config.installPath;
  }
  const local = findSmithRoot(process.cwd());
  if (local) return local;

  console.error(
    "Could not locate smith-core. Run this from within the smith-core directory,\n" +
    "or install with 'smith install' first."
  );
  process.exit(1);
}

function readEnv(smithRoot: string): Record<string, string> {
  const envPath = join(smithRoot, ".env");
  if (!existsSync(envPath)) {
    console.error(`No .env file found at ${envPath}`);
    console.error("Run 'smith install' to set up your environment.");
    process.exit(1);
  }
  return parseEnvFile(envPath);
}

function cmdToken(smithRoot: string): void {
  const vars = readEnv(smithRoot);
  const token = (vars.MCP_INDEX_API_TOKEN ?? "").trim();
  if (!token) {
    console.error("MCP_INDEX_API_TOKEN is not set in .env");
    console.error("Run 'smith install' to generate secure defaults.");
    process.exit(1);
  }
  console.log(token);
}

async function cmdPair(smithRoot: string, agentId: string, userId?: string): Promise<void> {
  const vars = readEnv(smithRoot);
  const adminToken = (vars.CHAT_BRIDGE_ADMIN_TOKEN ?? "").trim();
  if (!adminToken) {
    console.error("CHAT_BRIDGE_ADMIN_TOKEN is not set in .env");
    console.error("Run 'smith install' to generate secure defaults.");
    process.exit(1);
  }

  const port = (vars.CHAT_BRIDGE_WEBHOOK_PORT ?? "8092").trim();
  const url = `http://127.0.0.1:${port}/admin/pairing-codes`;

  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ agent_id: agentId, user_id: userId ?? null }),
    });
  } catch {
    console.error(`Could not connect to chat bridge at ${url}`);
    console.error("Make sure smith-chat-daemon is running:");
    console.error("  smith-chat-daemon");
    process.exit(1);
  }

  if (!resp.ok) {
    const body = await resp.text();
    console.error(`Chat bridge returned ${resp.status}: ${body}`);
    process.exit(1);
  }

  const data = (await resp.json()) as { code: string; agent_id: string; user_id?: string | null; expires_in: number };
  console.log();
  console.log(`  Pairing code:  ${data.code}`);
  console.log(`  Agent:         ${data.agent_id}`);
  if (data.user_id) {
    console.log(`  User:          ${data.user_id}`);
  }
  console.log(`  Expires in:    ${data.expires_in} seconds`);
  console.log();
  console.log("Send this code as a DM to your bot to pair or claim the invitation.");
  console.log();
}

async function cmdStatus(smithRoot: string): Promise<void> {
  const vars = readEnv(smithRoot);

  console.log();
  console.log(`  Smith root:    ${smithRoot}`);

  const natsUrl = (vars.SMITH_NATS_URL ?? vars.NATS_URL ?? "").trim();
  if (natsUrl) {
    try {
      const parsed = new URL(natsUrl);
      const authState = parsed.username || parsed.password ? "authenticated" : "unauthenticated";
      console.log(`  NATS:          ${parsed.protocol}//${parsed.host} (${authState})`);
    } catch {
      console.log(`  NATS:          ${natsUrl}`);
    }
  } else {
    console.log("  NATS:          (not configured)");
  }

  // MCP Index
  const mcpToken = (vars.MCP_INDEX_API_TOKEN ?? "").trim();
  const mcpPort = (vars.MCP_INDEX_PORT ?? "9200").trim();
  if (mcpToken) {
    console.log(`  MCP token:     ${mcpToken}`);
    console.log(`  MCP endpoint:  http://localhost:${mcpPort}/tools`);
  } else {
    console.log("  MCP token:     (not set)");
  }

  // Chat bridge
  const adminToken = (vars.CHAT_BRIDGE_ADMIN_TOKEN ?? "").trim();
  const webhookPort = (vars.CHAT_BRIDGE_WEBHOOK_PORT ?? "8092").trim();
  if (adminToken) {
    try {
      const resp = await fetch(`http://127.0.0.1:${webhookPort}/health`, {
        signal: AbortSignal.timeout(2000),
      });
      console.log(`  Chat bridge:   running (port ${webhookPort})`);
    } catch {
      console.log(`  Chat bridge:   not running (port ${webhookPort})`);
    }
  } else {
    console.log("  Chat bridge:   (not configured)");
  }

  const signedWebhooks = (vars.CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS ?? "").trim().toLowerCase();
  if (signedWebhooks === "false" || signedWebhooks === "0") {
    console.log("  Warning:       signed webhooks disabled");
  }

  console.log();
}

function printHelp(): void {
  console.log(`smith — Smith Core CLI

Usage: smith <command> [options]

Commands:
  install        AI-guided install/bootstrap workflow
  token          Print your MCP Index API token
  pair           Generate a chat bridge pairing code
  status         Show installation status and configuration

Options:
  install --non-interactive  Run installer in non-interactive mode
  install --harness <name>   Choose agent harness: pi, codex, claude, opencode
  pair --agent-id <id>   Agent ID for pairing (default: smith-default)
  pair --user-id <id>    Pre-authorize a specific Smith user to claim the token

Examples:
  smith install                     Run the installer
  smith install --harness codex     Use Codex instead of pi
  smith install --non-interactive   CI/headless bootstrap
  smith token                       Print token (pipe-friendly)
  smith pair                        Generate a pairing code
  smith pair --agent-id my-agent    Pair with a specific agent
  smith pair --user-id <uuid>       Generate a claim token for a pre-created user
  smith status                      Overview of your installation`);
}

async function main(): Promise<void> {
  const command = process.argv[2];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    process.exit(0);
  }

  switch (command) {
    case "install":
      await runInstallerCli([process.argv[0] ?? "node", "smith install", ...process.argv.slice(3)]);
      break;

    case "token": {
      const smithRoot = resolveSmithRoot();
      cmdToken(smithRoot);
      break;
    }

    case "pair": {
      const smithRoot = resolveSmithRoot();
      let agentId = "smith-default";
      let userId: string | undefined;
      const agentIdIdx = process.argv.indexOf("--agent-id");
      if (agentIdIdx !== -1 && process.argv[agentIdIdx + 1]) {
        agentId = process.argv[agentIdIdx + 1]!;
      }
      const userIdIdx = process.argv.indexOf("--user-id");
      if (userIdIdx !== -1 && process.argv[userIdIdx + 1]) {
        userId = process.argv[userIdIdx + 1]!;
      }
      await cmdPair(smithRoot, agentId, userId);
      break;
    }

    case "status": {
      const smithRoot = resolveSmithRoot();
      await cmdStatus(smithRoot);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      console.error("Run 'smith help' for usage.");
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
