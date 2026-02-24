#!/usr/bin/env node
//
// Wrapper around mcp-discord that adds discord_list_guild_members.
//
// The upstream mcp-discord npm package doesn't include a member-listing tool.
// This wrapper monkey-patches the tool list and dispatch to add one, then
// delegates everything else to the original server.
//

import { Client, GatewayIntentBits } from "discord.js";
import { DiscordMCPServer } from "mcp-discord/build/server.js";
import { StdioTransport } from "mcp-discord/build/transport.js";
import { toolList } from "mcp-discord/build/toolList.js";

// ── Add our tools to the upstream tool list ─────────────────────────────

toolList.push({
  name: "discord_list_guilds",
  description:
    "Lists all Discord servers (guilds) the bot is a member of. Returns guild IDs, names, member counts, and owner info. Use this to discover guild IDs before calling other guild-specific tools.",
  inputSchema: {
    type: "object",
    properties: {},
    required: [],
  },
});

toolList.push({
  name: "discord_list_guild_members",
  description:
    "Lists members of a Discord server (guild). Returns user IDs, usernames, display names, roles, and join dates. Requires the GuildMembers privileged intent.",
  inputSchema: {
    type: "object",
    properties: {
      guildId: { type: "string", description: "Discord guild (server) ID" },
      limit: {
        type: "number",
        minimum: 1,
        maximum: 1000,
        default: 100,
        description: "Maximum number of members to return (default 100, max 1000)",
      },
    },
    required: ["guildId"],
  },
});

// ── Create Discord client with GuildMembers intent ──────────────────────

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
  ],
});

const token = process.env.DISCORD_TOKEN;
if (token) {
  client.token = token;
  try {
    await client.login(token);
    console.error("[discord-wrapper] logged in to Discord");
  } catch (err) {
    console.error("[discord-wrapper] auto-login failed:", String(err));
  }
} else {
  console.error("[discord-wrapper] no DISCORD_TOKEN, skipping auto-login");
}

// ── Create server and patch in our handler ──────────────────────────────

const transport = new StdioTransport();
const mcpServer = new DiscordMCPServer(client, transport);

// Monkey-patch the internal handler map to intercept tools/call
const originalCallHandler = mcpServer.server._requestHandlers.get("tools/call");
mcpServer.server._requestHandlers.set("tools/call", async (request, extra) => {
  const { name, arguments: args } = request.params;

  if (name === "discord_list_guilds") {
    return listGuildsHandler({ client });
  }

  if (name === "discord_list_guild_members") {
    return listGuildMembersHandler(args, { client });
  }

  // Delegate to original handler
  return originalCallHandler(request, extra);
});

// ── Handlers ────────────────────────────────────────────────────────────

async function listGuildsHandler(context) {
  try {
    if (!context.client.isReady()) {
      return {
        content: [{ type: "text", text: "Discord client not logged in." }],
        isError: true,
      };
    }

    const guilds = await context.client.guilds.fetch();

    const formatted = guilds.map((g) => ({
      id: g.id,
      name: g.name,
      icon: g.iconURL(),
      memberCount: g.approximateMemberCount ?? null,
    }));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { guildCount: formatted.length, guilds: formatted },
            null,
            2
          ),
        },
      ],
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error listing guilds: ${msg}` }],
      isError: true,
    };
  }
}

async function listGuildMembersHandler(args, context) {
  try {
    if (!context.client.isReady()) {
      return {
        content: [{ type: "text", text: "Discord client not logged in." }],
        isError: true,
      };
    }

    const guildId = args.guildId;
    const limit = Math.min(args.limit ?? 100, 1000);

    const guild = await context.client.guilds.fetch(guildId);
    if (!guild) {
      return {
        content: [
          { type: "text", text: `Cannot find guild with ID: ${guildId}` },
        ],
        isError: true,
      };
    }

    const members = await guild.members.fetch({ limit });

    const formatted = members.map((m) => ({
      id: m.id,
      username: m.user.username,
      displayName: m.displayName,
      bot: m.user.bot,
      roles: m.roles.cache
        .filter((r) => r.name !== "@everyone")
        .map((r) => ({ id: r.id, name: r.name })),
      joinedAt: m.joinedAt?.toISOString() ?? null,
    }));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { guildId, memberCount: formatted.length, members: formatted },
            null,
            2
          ),
        },
      ],
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error listing guild members: ${msg}` }],
      isError: true,
    };
  }
}

// ── Start ───────────────────────────────────────────────────────────────

try {
  await mcpServer.start();
  console.error("[discord-wrapper] MCP server started");
} catch (err) {
  console.error("[discord-wrapper] failed to start:", String(err));
  process.exit(1);
}
