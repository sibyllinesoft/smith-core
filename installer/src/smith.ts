#!/usr/bin/env node

import { existsSync } from "fs";
import { join } from "path";
import { findSmithRoot, readSmithConfig, parseEnvFile } from "./lib.js";

function resolveSmithRoot(): string {
  const config = readSmithConfig();
  if (config && existsSync(config.installPath)) {
    return config.installPath;
  }
  const local = findSmithRoot(process.cwd());
  if (local) return local;

  console.error(
    "Could not locate smith-core. Run this from within the smith-core directory,\n" +
    "or install with smith-install first."
  );
  process.exit(1);
}

function readEnv(smithRoot: string): Record<string, string> {
  const envPath = join(smithRoot, ".env");
  if (!existsSync(envPath)) {
    console.error(`No .env file found at ${envPath}`);
    console.error("Run smith-install to set up your environment.");
    process.exit(1);
  }
  return parseEnvFile(envPath);
}

function cmdToken(smithRoot: string): void {
  const vars = readEnv(smithRoot);
  const token = (vars.MCP_INDEX_API_TOKEN ?? "").trim();
  if (!token) {
    console.error("MCP_INDEX_API_TOKEN is not set in .env");
    console.error("Run smith-install to generate secure defaults.");
    process.exit(1);
  }
  console.log(token);
}

async function cmdPair(smithRoot: string, agentId: string): Promise<void> {
  const vars = readEnv(smithRoot);
  const adminToken = (vars.CHAT_BRIDGE_ADMIN_TOKEN ?? "").trim();
  if (!adminToken) {
    console.error("CHAT_BRIDGE_ADMIN_TOKEN is not set in .env");
    console.error("Run smith-install to generate secure defaults.");
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
      body: JSON.stringify({ agent_id: agentId }),
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

  const data = (await resp.json()) as { code: string; agent_id: string; expires_in: number };
  console.log();
  console.log(`  Pairing code:  ${data.code}`);
  console.log(`  Agent:         ${data.agent_id}`);
  console.log(`  Expires in:    ${data.expires_in} seconds`);
  console.log();
  console.log("Send this code as a DM to your bot to pair.");
  console.log();
}

async function cmdStatus(smithRoot: string): Promise<void> {
  const vars = readEnv(smithRoot);

  console.log();
  console.log(`  Smith root:    ${smithRoot}`);

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

  console.log();
}

function printHelp(): void {
  console.log(`smith — Smith Core CLI

Usage: smith <command> [options]

Commands:
  token          Print your MCP Index API token
  pair           Generate a chat bridge pairing code
  status         Show installation status and configuration

Options:
  pair --agent-id <id>   Agent ID for pairing (default: smith-default)

Examples:
  smith token                       Print token (pipe-friendly)
  smith pair                        Generate a pairing code
  smith pair --agent-id my-agent    Pair with a specific agent
  smith status                      Overview of your installation`);
}

async function main(): Promise<void> {
  const command = process.argv[2];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    process.exit(0);
  }

  const smithRoot = resolveSmithRoot();

  switch (command) {
    case "token":
      cmdToken(smithRoot);
      break;

    case "pair": {
      let agentId = "smith-default";
      const agentIdIdx = process.argv.indexOf("--agent-id");
      if (agentIdIdx !== -1 && process.argv[agentIdIdx + 1]) {
        agentId = process.argv[agentIdIdx + 1]!;
      }
      await cmdPair(smithRoot, agentId);
      break;
    }

    case "status":
      await cmdStatus(smithRoot);
      break;

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
