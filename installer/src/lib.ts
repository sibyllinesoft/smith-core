import { existsSync, readFileSync, readdirSync, statSync } from "fs";
import { resolve, join } from "path";

import type { KnownProvider } from "@mariozechner/pi-ai";
import type { ThinkingLevel } from "@mariozechner/pi-agent-core";

export type { KnownProvider, ThinkingLevel };

export interface CliArgs {
  nonInteractive: boolean;
  provider: KnownProvider;
  model: string;
  thinkingLevel: ThinkingLevel;
  step?: string;
  force: boolean;
  help: boolean;
  repo?: string;
}

export interface InstallerOptions {
  /** Path to smith-core repo root */
  smithRoot: string;
  /** LLM provider (default: anthropic) */
  provider?: KnownProvider;
  /** Model ID (default: claude-sonnet-4-20250514) */
  model?: string;
  /** Thinking level (default: medium) */
  thinkingLevel?: ThinkingLevel;
  /** Single step prefix to run */
  step?: string;
  /** Ignore idempotency markers */
  force?: boolean;
  /** Non-blocking local security warnings to surface in agent instructions */
  securityWarnings?: string[];
}

export interface Skill {
  name: string;
  description: string;
  content: string;
}

export interface InstallerSecurityWarning {
  id: string;
  message: string;
  recommendation: string;
}

export interface InstallerSecurityReport {
  sourceFile: string | null;
  warnings: InstallerSecurityWarning[];
}

export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    nonInteractive: false,
    provider: "anthropic" as KnownProvider,
    model: "claude-sonnet-4-20250514",
    thinkingLevel: "medium" as ThinkingLevel,
    force: false,
    help: false,
  };

  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case "--non-interactive":
        args.nonInteractive = true;
        break;
      case "--provider":
        args.provider = argv[++i]! as KnownProvider;
        break;
      case "--model":
        args.model = argv[++i]!;
        break;
      case "--thinking":
        args.thinkingLevel = argv[++i]! as ThinkingLevel;
        break;
      case "--step":
        args.step = argv[++i]!;
        break;
      case "--force":
        args.force = true;
        break;
      case "--repo":
        args.repo = argv[++i]!;
        break;
      case "--help":
      case "-h":
        args.help = true;
        break;
      default:
        throw new Error(`Unknown option: ${argv[i]} (try --help)`);
    }
  }

  return args;
}

export function findSmithRoot(startDir: string): string | null {
  let dir = resolve(startDir);
  const root = resolve("/");

  while (dir !== root) {
    const looksLikeRepoRoot =
      existsSync(join(dir, "Cargo.toml")) &&
      existsSync(join(dir, "docker-compose.yaml")) &&
      existsSync(join(dir, "justfile")) &&
      existsSync(join(dir, "installer", "package.json"));

    if (looksLikeRepoRoot) {
      return dir;
    }
    dir = resolve(dir, "..");
  }

  return null;
}

export function loadSkills(skillsDir: string): Skill[] {
  const skills: Skill[] = [];

  let entries: string[];
  try {
    entries = readdirSync(skillsDir);
  } catch {
    return skills;
  }

  for (const entry of entries) {
    const skillDir = join(skillsDir, entry);
    const skillFile = join(skillDir, "SKILL.md");

    try {
      if (!statSync(skillDir).isDirectory()) continue;
      const content = readFileSync(skillFile, "utf8");

      // Extract description from frontmatter
      const match = content.match(/^---\s*\ndescription:\s*(.+)\n---/);
      const description = match?.[1] ?? entry;

      skills.push({ name: entry, description, content });
    } catch {
      // Skip skills without SKILL.md
    }
  }

  return skills;
}

export function buildSystemPrompt(opts: InstallerOptions): string {
  let prompt = "You are the Smith Core installer and configuration agent.\n\n";
  prompt += `smith-core repo root: ${opts.smithRoot}\n`;

  if (process.platform === "darwin") {
    prompt +=
      "\nThis host is macOS. Ensure Gondolin-backed persistent VM sessions are enabled by setting:\n" +
      "- SMITH_EXECUTOR_VM_POOL_ENABLED=true\n" +
      "- SMITH_EXECUTOR_VM_METHOD=gondolin\n" +
      "- SMITH_EXECUTOR_GONDOLIN_COMMAND=gondolin\n" +
      "- SMITH_EXECUTOR_GONDOLIN_ARGS=exec,--\n";
  }

  if (opts.step) {
    prompt += `\nThe user wants to run installer step '${opts.step}' only.\n`;
  }

  const configSteps = ["configure-policy", "policy"];
  if (opts.step && configSteps.includes(opts.step.toLowerCase())) {
    prompt += "You are in configuration mode (not bootstrapping). " +
      "Focus on inspecting and configuring the policy system. " +
      "Do not run build or infrastructure setup commands.\n";
  }

  if (opts.force) {
    prompt += "--force is set — recreate infrastructure before bootstrapping.\n";
  }
  if (opts.securityWarnings && opts.securityWarnings.length > 0) {
    prompt +=
      "\nLocal security posture warnings were detected. These are non-blocking, " +
      "but you must present them clearly before continuing:\n";
    for (const warning of opts.securityWarnings) {
      prompt += `- ${warning}\n`;
    }
    prompt +=
      "Explicitly warn when deployment is not on a private network and recommend " +
      "VPN/tunnel controls (for example Cloudflare Tunnel or Tailscale).\n";
  }

  return prompt;
}

function parseEnvFile(path: string): Record<string, string> {
  const vars: Record<string, string> = {};
  const content = readFileSync(path, "utf8");
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    vars[key] = value;
  }
  return vars;
}

function hasNonEmpty(vars: Record<string, string>, keys: string[]): boolean {
  return keys.some((key) => (vars[key] ?? "").trim().length > 0);
}

function looksLikeWeakSecret(value: string, weakValues: string[]): boolean {
  const normalized = value.trim();
  return normalized.length === 0 || weakValues.includes(normalized);
}

function looksLikeWeakToken(value: string, minLength = 24): boolean {
  const normalized = value.trim();
  const lower = normalized.toLowerCase();
  if (normalized.length < minLength) {
    return true;
  }
  return (
    lower.startsWith("change-me") ||
    lower.startsWith("changeme") ||
    lower.startsWith("replace-with-")
  );
}

function isLikelyLoopbackListen(value: string): boolean {
  const v = value.trim().toLowerCase();
  return (
    v.includes("127.0.0.1") ||
    v.includes("localhost") ||
    v.includes("[::1]") ||
    v === "::1" ||
    v.startsWith("::1:")
  );
}

export function evaluateInstallerSecurity(smithRoot: string): InstallerSecurityReport {
  const envPath = join(smithRoot, ".env");
  const envExamplePath = join(smithRoot, ".env.example");

  const sourceFile = existsSync(envPath)
    ? envPath
    : existsSync(envExamplePath)
      ? envExamplePath
      : null;

  if (!sourceFile) {
    return {
      sourceFile: null,
      warnings: [
        {
          id: "missing-env",
          message: "No .env or .env.example was found to evaluate security posture.",
          recommendation:
            "Create .env from .env.example and review secrets plus network exposure settings.",
        },
      ],
    };
  }

  const vars = parseEnvFile(sourceFile);
  const warnings: InstallerSecurityWarning[] = [];

  const weakSecrets: Array<[string, string[], string]> = [
    [
      "POSTGRES_PASSWORD",
      ["smith-dev", "postgres", "password", "changeme"],
      "Set POSTGRES_PASSWORD to a unique, high-entropy value.",
    ],
    [
      "CLICKHOUSE_PASSWORD",
      ["observability-dev", "clickhouse", "password", "changeme"],
      "Set CLICKHOUSE_PASSWORD to a unique, high-entropy value.",
    ],
    [
      "GRAFANA_ADMIN_PASSWORD",
      ["admin", "grafana", "password", "changeme"],
      "Set GRAFANA_ADMIN_PASSWORD to a unique, high-entropy value.",
    ],
  ];

  for (const [key, weakValues, recommendation] of weakSecrets) {
    const value = (vars[key] ?? "").trim();
    if (looksLikeWeakSecret(value, weakValues)) {
      warnings.push({
        id: `weak-${key.toLowerCase()}`,
        message: `${key} is empty or set to a known weak default.`,
        recommendation,
      });
    }
  }

  const mcpToken = (vars.MCP_INDEX_API_TOKEN ?? "").trim();
  if (looksLikeWeakToken(mcpToken, 24)) {
    warnings.push({
      id: "weak-mcp-index-token",
      message:
        "MCP_INDEX_API_TOKEN is missing or too short; MCP index APIs may be unauthenticated or weakly protected.",
      recommendation:
        "Set MCP_INDEX_API_TOKEN to a long random secret (at least 24 characters).",
    });
  }

  const mcpSidecarToken = (vars.MCP_SIDECAR_API_TOKEN ?? "").trim();
  if (looksLikeWeakToken(mcpSidecarToken, 24)) {
    warnings.push({
      id: "weak-mcp-sidecar-token",
      message:
        "MCP_SIDECAR_API_TOKEN is missing or too short; MCP sidecar APIs may be unauthenticated or weakly protected.",
      recommendation:
        "Set MCP_SIDECAR_API_TOKEN to a long random secret (at least 24 characters).",
    });
  }

  const indexAllowUnauth = (vars.MCP_INDEX_ALLOW_UNAUTHENTICATED ?? "")
    .trim()
    .toLowerCase();
  if (indexAllowUnauth === "true" || indexAllowUnauth === "1") {
    warnings.push({
      id: "mcp-index-unauth-enabled",
      message:
        "MCP_INDEX_ALLOW_UNAUTHENTICATED is enabled; mcp-index APIs can be called without a token.",
      recommendation:
        "Set MCP_INDEX_ALLOW_UNAUTHENTICATED=false in production and keep MCP_INDEX_API_TOKEN set.",
    });
  }

  const sidecarAllowUnauth = (vars.MCP_SIDECAR_ALLOW_UNAUTHENTICATED ?? "")
    .trim()
    .toLowerCase();
  if (sidecarAllowUnauth === "true" || sidecarAllowUnauth === "1") {
    warnings.push({
      id: "mcp-sidecar-unauth-enabled",
      message:
        "MCP_SIDECAR_ALLOW_UNAUTHENTICATED is enabled; mcp-sidecar APIs can be called without a token.",
      recommendation:
        "Set MCP_SIDECAR_ALLOW_UNAUTHENTICATED=false in production and keep MCP_SIDECAR_API_TOKEN set.",
    });
  }

  const webhookStrict = (vars.CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS ?? "")
    .trim()
    .toLowerCase();
  if (webhookStrict === "false" || webhookStrict === "0") {
    warnings.push({
      id: "chat-webhook-signature-disabled",
      message:
        "CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS is disabled; webhook ingress accepts unsigned requests.",
      recommendation:
        "Set CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS=true and configure provider secrets/public keys.",
    });
  }

  const adminToken = (vars.CHAT_BRIDGE_ADMIN_TOKEN ?? "").trim();
  if (looksLikeWeakToken(adminToken, 24)) {
    warnings.push({
      id: "weak-chat-bridge-admin-token",
      message:
        "CHAT_BRIDGE_ADMIN_TOKEN is missing or too short; pairing admin endpoint protection may be weak.",
      recommendation:
        "Set CHAT_BRIDGE_ADMIN_TOKEN to a long random secret (at least 24 characters).",
    });
  }

  const capabilityDigest = (vars.AGENTD_CAPABILITY_DIGEST ?? "").trim();
  if (!/^[a-fA-F0-9]{64}$/.test(capabilityDigest)) {
    warnings.push({
      id: "invalid-capability-digest",
      message:
        "AGENTD_CAPABILITY_DIGEST is missing or not a valid 64-character hex digest.",
      recommendation:
        "Set AGENTD_CAPABILITY_DIGEST to the intended capability bundle digest before production use.",
    });
  } else if (/^0{64}$/.test(capabilityDigest)) {
    warnings.push({
      id: "zero-capability-digest",
      message: "AGENTD_CAPABILITY_DIGEST is all zeros and will be rejected by secure defaults.",
      recommendation:
        "Set AGENTD_CAPABILITY_DIGEST to a real digest, or only allow zero in local development overrides.",
    });
  }

  const cloudflareKeys = [
    "CLOUDFLARED_TUNNEL_TOKEN",
    "CLOUDFLARE_TUNNEL_TOKEN",
    "CLOUDFLARE_TUNNEL_ID",
    "CLOUDFLARE_TUNNEL_HOSTNAME",
    "CLOUDFLARE_TUNNEL_E2E_URL",
    "CF_TUNNEL_TOKEN",
    "TUNNEL_TOKEN",
  ];
  const tailscaleKeys = [
    "TAILSCALE_AUTHKEY",
    "TS_AUTHKEY",
    "TAILSCALE_OAUTH_CLIENT_ID",
    "TAILSCALE_HOSTNAME",
    "TAILSCALE_TUNNEL_E2E_URL",
  ];
  const hasCloudflare = hasNonEmpty(vars, cloudflareKeys);
  const hasTailscale = hasNonEmpty(vars, tailscaleKeys);

  if (!hasCloudflare && !hasTailscale) {
    warnings.push({
      id: "missing-private-network-indicator",
      message:
        "No Cloudflare Tunnel or Tailscale configuration indicators were found.",
      recommendation:
        "Use a private network path (VPN/tunnel), and avoid exposing management endpoints directly to public networks.",
    });
  }

  const grpcListen = (vars.AGENTD_GRPC_LISTEN ?? "").trim();
  if (grpcListen && !isLikelyLoopbackListen(grpcListen)) {
    warnings.push({
      id: "agentd-grpc-non-loopback",
      message: `AGENTD_GRPC_LISTEN is set to a non-loopback address (${grpcListen}).`,
      recommendation:
        "Keep AGENTD_GRPC_LISTEN on loopback or enforce network controls before exposing it beyond trusted private networks.",
    });
  }

  return { sourceFile, warnings };
}
