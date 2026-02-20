#!/usr/bin/env node

import { copyFileSync, createWriteStream, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "fs";
import { resolve, join } from "path";
import { execFileSync } from "child_process";
import { pipeline } from "stream/promises";
import { randomBytes } from "crypto";
import { tmpdir, homedir } from "os";
import { createInterface } from "readline/promises";
import { createServer } from "net";
import { createInstallerSession } from "./agents.js";
import { parseArgs, findSmithRoot, evaluateInstallerSecurity, readSmithConfig, writeSmithConfig } from "./lib.js";
import type { CliArgs } from "./lib.js";

type CommandSpec = {
  command: string;
  args: string[];
};

const DEFAULT_REPO = "sibyllinesoft/smith-core";

async function resolveLatestTag(repo: string): Promise<string> {
  const resp = await fetch(
    `https://api.github.com/repos/${repo}/tags?per_page=100`,
    { headers: { "User-Agent": "smith-installer" } }
  );
  if (!resp.ok) {
    throw new Error(`Failed to fetch tags from ${repo}: ${resp.status}`);
  }
  const tags = (await resp.json()) as Array<{ name: string }>;
  const semverTags = tags
    .map((t) => t.name)
    .filter((name) => /^v?\d+\.\d+\.\d+$/.test(name));
  if (semverTags.length === 0) {
    throw new Error(`No semver tags found in ${repo}`);
  }
  semverTags.sort((a, b) => {
    const pa = a.replace(/^v/, "").split(".").map(Number);
    const pb = b.replace(/^v/, "").split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      if (pa[i]! !== pb[i]!) return pb[i]! - pa[i]!;
    }
    return 0;
  });
  return semverTags[0]!;
}

async function downloadRepo(repo: string, tag: string): Promise<string> {
  const target = resolve(process.cwd(), "smith-core");
  const tarballUrl = `https://github.com/${repo}/archive/refs/tags/${tag}.tar.gz`;

  console.log(`[installer] Downloading ${repo}@${tag} ...`);
  const resp = await fetch(tarballUrl);
  if (!resp.ok) {
    throw new Error(`Failed to download ${tarballUrl}: ${resp.status}`);
  }

  const tmpFile = join(tmpdir(), `smith-core-${tag}.tar.gz`);
  const fileStream = createWriteStream(tmpFile);
  await pipeline(resp.body as any, fileStream);

  mkdirSync(target, { recursive: true });
  execFileSync("tar", ["xzf", tmpFile, "--strip-components=1", "-C", target], {
    stdio: "inherit",
  });
  unlinkSync(tmpFile);

  console.log(`[installer] Extracted ${repo}@${tag} to ${target}`);
  return target;
}

function providerEnvKey(provider: string): string {
  const map: Record<string, string> = {
    anthropic: "ANTHROPIC_API_KEY",
    openai: "OPENAI_API_KEY",
    google: "GEMINI_API_KEY",
    "azure-openai": "AZURE_OPENAI_API_KEY",
    groq: "GROQ_API_KEY",
  };
  return map[provider] ?? `${provider.toUpperCase().replace(/-/g, "_")}_API_KEY`;
}

async function ensureProviderApiKey(provider: string): Promise<void> {
  const envKey = providerEnvKey(provider);
  if (process.env[envKey]) return;

  // If pi auth storage exists the user has logged in before
  const authPath = join(homedir(), ".pi", "agent", "auth.json");
  if (existsSync(authPath)) return;

  console.log(`
┌─────────────────────────────────────────────────────────┐
│  Smith Core Installer                                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  This installer uses an AI agent to guide you through   │
│  setting up your Smith Core development environment.    │
│                                                         │
│  The agent will:                                        │
│    · Configure infrastructure (Docker, databases)       │
│    · Build Rust and Node workspaces                     │
│    · Set up security defaults and certificates          │
│    · Verify your installation                           │
│                                                         │
│  An API key for your AI provider is required.           │
└─────────────────────────────────────────────────────────┘
`);

  if (!process.stdin.isTTY) {
    console.error(`Error: No API key found. Set ${envKey} in your environment.`);
    process.exit(1);
  }

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const key = await rl.question(`Enter your ${provider} API key (${envKey}): `);
    if (!key.trim()) {
      console.error("No API key provided. Exiting.");
      process.exit(1);
    }
    process.env[envKey] = key.trim();
    console.log(`[installer] ${envKey} set for this session.\n`);
  } finally {
    rl.close();
  }
}

function runCommand(cwd: string, spec: CommandSpec): void {
  execFileSync(spec.command, spec.args, {
    cwd,
    stdio: "inherit",
    env: process.env,
  });
}

function ensureEnvFile(smithRoot: string): string | null {
  const envPath = join(smithRoot, ".env");
  if (existsSync(envPath)) {
    return envPath;
  }

  const examplePath = join(smithRoot, ".env.example");
  if (!existsSync(examplePath)) {
    return null;
  }

  copyFileSync(examplePath, envPath);
  console.log(`[installer] Created ${envPath} from .env.example`);
  return envPath;
}

function parseEnvFile(path: string): Record<string, string> {
  const vars: Record<string, string> = {};
  if (!existsSync(path)) {
    return vars;
  }

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

function upsertEnvValue(path: string, key: string, value: string): void {
  const current = existsSync(path) ? readFileSync(path, "utf8") : "";
  const lines = current.length > 0 ? current.split("\n") : [];
  const rendered = `${key}=${value}`;
  let replaced = false;

  const updated = lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      return line;
    }
    const eq = line.indexOf("=");
    if (eq <= 0) {
      return line;
    }
    const existingKey = line.slice(0, eq).trim();
    if (existingKey !== key) {
      return line;
    }
    replaced = true;
    return rendered;
  });

  if (!replaced) {
    if (updated.length > 0 && updated[updated.length - 1] !== "") {
      updated.push("");
    }
    updated.push(rendered);
  }

  writeFileSync(path, `${updated.join("\n")}\n`);
}

function isCommandAvailable(cmd: string): boolean {
  try {
    execFileSync(cmd, ["--version"], { stdio: "ignore", env: process.env });
    return true;
  } catch {
    return false;
  }
}

type NodeVersionManagerInfo = {
  name: "nvm" | "fnm";
  dir: string;
} | null;

function detectNodeVersionManager(): NodeVersionManagerInfo {
  // fnm is a standalone binary
  try {
    execFileSync("fnm", ["--version"], { stdio: "ignore" });
    return { name: "fnm", dir: "" };
  } catch {}

  // nvm is a shell function sourced from NVM_DIR/nvm.sh
  const nvmDir = process.env.NVM_DIR || join(homedir(), ".nvm");
  if (existsSync(join(nvmDir, "nvm.sh"))) {
    return { name: "nvm", dir: nvmDir };
  }

  return null;
}

const REQUIRED_PORTS: Array<[number, string]> = [
  [4222, "NATS"],
  [5432, "PostgreSQL"],
  [3000, "Grafana"],
  [9200, "MCP Index"],
  [6173, "Envoy mTLS Gateway"],
  [9901, "Envoy Admin"],
];

function checkPortAvailable(port: number, host = "127.0.0.1"): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => {
      server.close();
      resolve(true);
    });
    server.listen(port, host);
  });
}

async function runPreflightChecks(): Promise<void> {
  const errors: string[] = [];

  // Check Docker
  if (!isCommandAvailable("docker")) {
    errors.push("Docker is not installed or not in PATH. Install from https://docs.docker.com/get-docker/");
  } else {
    try {
      execFileSync("docker", ["info"], { stdio: "ignore", env: process.env });
    } catch {
      errors.push("Docker daemon is not running. Start Docker Desktop or the Docker service.");
    }
  }

  // Check docker compose
  try {
    execFileSync("docker", ["compose", "version"], { stdio: "ignore", env: process.env });
  } catch {
    errors.push("'docker compose' not available. Install Docker Compose v2: https://docs.docker.com/compose/install/");
  }

  // Check Node.js version (need >=20 for fetch, crypto, etc.)
  const nodeVersion = process.versions.node;
  const major = parseInt(nodeVersion.split(".")[0]!, 10);
  if (major < 20) {
    errors.push(
      `Node.js v${nodeVersion} detected but >=20 is required (>=22 recommended).\n` +
      `    Install with nvm:  nvm install 22 && nvm use 22\n` +
      `    Install with fnm:  fnm install 22 && fnm use 22\n` +
      `    Or download from:  https://nodejs.org/`
    );
  }

  if (errors.length > 0) {
    console.error("\n[preflight] Missing prerequisites:\n");
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    console.error("");
    process.exit(1);
  }

  console.log(`[preflight] Docker OK, Node.js ${nodeVersion} OK`);

  if (major < 22) {
    const versionManager = detectNodeVersionManager();
    if (versionManager) {
      const cmd = versionManager.name;
      console.warn(
        `\n[preflight] Warning: Node.js v${nodeVersion} detected — runtime services require Node >= 22.\n` +
        `[preflight] Affected: pi-bridge, smith-cron, session-recorder (local dev only;\n` +
        `[preflight] Docker containers use Node 22 regardless).\n` +
        `[preflight] Detected ${cmd}. Upgrade with: ${cmd} install 22 && ${cmd} use 22\n`
      );
    } else {
      console.warn(
        `\n[preflight] Warning: Node.js v${nodeVersion} detected — runtime services require Node >= 22.\n` +
        `[preflight] Affected: pi-bridge, smith-cron, session-recorder (local dev only;\n` +
        `[preflight] Docker containers use Node 22 regardless).\n` +
        `[preflight] No version manager (nvm/fnm) detected — the installer agent can help set one up.\n`
      );
    }
  }

  // Check port availability for Docker services
  const portConflicts: Array<[number, string]> = [];
  for (const [port, service] of REQUIRED_PORTS) {
    const available = await checkPortAvailable(port);
    if (!available) {
      portConflicts.push([port, service]);
    }
  }

  if (portConflicts.length > 0) {
    console.warn("\n[preflight] Port conflicts detected — these ports are already in use:");
    for (const [port, service] of portConflicts) {
      console.warn(`[preflight]   :${port} (${service})`);
    }
    console.warn(
      `[preflight]\n` +
      `[preflight] Docker Compose will fail if these ports are not freed.\n` +
      `[preflight] To identify the process: ss -tlnp 'sport = :PORT' (Linux)\n` +
      `[preflight]                          lsof -iTCP:PORT -sTCP:LISTEN (macOS)\n` +
      `[preflight] If a previous smith-core stack is running: docker compose down\n`
    );
  }
}

function ensureMacOsGondolinDefaults(smithRoot: string): void {
  if (process.platform !== "darwin") {
    return;
  }

  const envPath = ensureEnvFile(smithRoot);
  if (!envPath) {
    console.warn(
      "[installer] .env.example not found; skipping macOS Gondolin defaults."
    );
    return;
  }

  // Check if gondolin is already available
  let gondolinAvailable = false;
  try {
    execFileSync("gondolin", ["help"], { stdio: "ignore", env: process.env });
    gondolinAvailable = true;
  } catch {
    // Not available — try to install
  }

  if (!gondolinAvailable) {
    console.log("[installer] Gondolin not found. Attempting to install...");

    // Ensure qemu prerequisite
    if (!isCommandAvailable("qemu-system-aarch64")) {
      console.log("[installer] Installing qemu via Homebrew...");
      try {
        execFileSync("brew", ["install", "qemu"], { stdio: "inherit", env: process.env });
      } catch {
        console.warn(
          "[installer] Could not install qemu. Install it manually: brew install qemu\n" +
          "[installer] Skipping Gondolin setup — the agent can configure it later."
        );
        return;
      }
    }

    // Install gondolin
    try {
      console.log("[installer] Installing @earendil-works/gondolin globally...");
      execFileSync("npm", ["install", "-g", "@earendil-works/gondolin"], {
        stdio: "inherit",
        env: process.env,
      });
    } catch {
      console.warn(
        "[installer] Could not install Gondolin. Install it manually: npm install -g @earendil-works/gondolin\n" +
        "[installer] Skipping Gondolin setup — the agent can configure it later."
      );
      return;
    }
  }

  upsertEnvValue(envPath, "SMITH_EXECUTOR_VM_POOL_ENABLED", "true");
  upsertEnvValue(envPath, "SMITH_EXECUTOR_VM_METHOD", "gondolin");
  upsertEnvValue(envPath, "SMITH_EXECUTOR_GONDOLIN_COMMAND", "gondolin");
  upsertEnvValue(envPath, "SMITH_EXECUTOR_GONDOLIN_ARGS", "exec,--");

  console.log(
    "[installer] macOS detected: enabled persistent VM pool and Gondolin defaults in .env"
  );
}

function isLikelyPlaceholderSecret(value: string, minLength = 24): boolean {
  const normalized = value.trim();
  const lower = normalized.toLowerCase();
  if (normalized.length < minLength) return true;
  if (
    lower.startsWith("change-me") ||
    lower.startsWith("changeme") ||
    lower.startsWith("replace-with-")
  ) {
    return true;
  }
  return false;
}

function generateHexSecret(bytes = 24): string {
  return randomBytes(bytes).toString("hex");
}

function ensureSecurityDefaults(smithRoot: string): void {
  const envPath = ensureEnvFile(smithRoot);
  if (!envPath) return;

  const vars = parseEnvFile(envPath);
  const generated: string[] = [];
  const configured: string[] = [];

  const ensureToken = (
    key: string,
    bytes = 24,
    minLength = 24
  ): void => {
    const current = (vars[key] ?? "").trim();
    if (isLikelyPlaceholderSecret(current, minLength)) {
      const value = generateHexSecret(bytes);
      upsertEnvValue(envPath, key, value);
      vars[key] = value;
      generated.push(key);
    }
  };

  const ensureValue = (key: string, value: string): void => {
    const current = (vars[key] ?? "").trim();
    if (current.length === 0) {
      upsertEnvValue(envPath, key, value);
      vars[key] = value;
      configured.push(key);
    }
  };

  // Database / service password hardening — replace known weak defaults
  const weakPasswords: Array<[string, string[]]> = [
    ["POSTGRES_PASSWORD", ["smith-dev", "postgres", "password", "changeme"]],
    ["CLICKHOUSE_PASSWORD", ["observability-dev", "clickhouse", "password", "changeme"]],
    ["GRAFANA_ADMIN_PASSWORD", ["admin", "grafana", "password", "changeme"]],
  ];

  for (const [key, weakValues] of weakPasswords) {
    const current = (vars[key] ?? "").trim();
    if (current.length === 0 || weakValues.includes(current)) {
      const newPassword = generateHexSecret(16); // 32-char hex
      upsertEnvValue(envPath, key, newPassword);

      // Update connection strings that embed the old password
      if (key === "POSTGRES_PASSWORD" && current.length > 0) {
        const connKeys = ["SMITH_DATABASE_URL", "PI_BRIDGE_PG"];
        for (const connKey of connKeys) {
          const connStr = (vars[connKey] ?? "").trim();
          if (connStr && connStr.includes(`:${current}@`)) {
            const updated = connStr.replace(`:${current}@`, `:${newPassword}@`);
            upsertEnvValue(envPath, connKey, updated);
            vars[connKey] = updated;
          }
        }
      }

      vars[key] = newPassword;
      generated.push(key);
    }
  }

  // MCP index / sidecar API hardening
  ensureToken("MCP_INDEX_API_TOKEN", 24, 24);
  ensureToken("MCP_SIDECAR_API_TOKEN", 24, 24);
  ensureValue("MCP_INDEX_ALLOW_UNAUTHENTICATED", "false");
  ensureValue("MCP_SIDECAR_ALLOW_UNAUTHENTICATED", "false");

  // Chat webhook hardening defaults
  ensureValue("CHAT_BRIDGE_REQUIRE_SIGNED_WEBHOOKS", "true");
  ensureValue("CHAT_BRIDGE_GITHUB_INGEST_SUBJECT", "smith.orch.ingest.github");
  ensureToken("CHAT_BRIDGE_ADMIN_TOKEN", 24, 24);
  ensureToken("CHAT_BRIDGE_GITHUB_WEBHOOK_SECRET", 24, 24);
  ensureToken("CHAT_BRIDGE_TELEGRAM_WEBHOOK_SECRET", 16, 20);
  ensureToken("CHAT_BRIDGE_WHATSAPP_VERIFY_TOKEN", 16, 20);
  ensureToken("CHAT_BRIDGE_WHATSAPP_APP_SECRET", 24, 24);

  if (generated.length > 0 || configured.length > 0) {
    const details = [
      generated.length > 0
        ? `generated secrets: ${generated.join(", ")}`
        : null,
      configured.length > 0
        ? `configured defaults: ${configured.join(", ")}`
        : null,
    ]
      .filter(Boolean)
      .join("; ");
    console.log(`[installer] Applied security defaults in .env (${details})`);
  }
}

function tryInstallSmithServices(smithRoot: string): void {
  const platform = process.platform;
  const arch = process.arch;
  const platformTag = `${platform}-${arch}`;
  const supported: Record<string, string> = {
    "linux-x64": "@sibyllinesoft/smith-services-linux-x64",
    "darwin-arm64": "@sibyllinesoft/smith-services-darwin-arm64",
  };

  if (!supported[platformTag]) {
    console.warn(
      `[installer] smith-services: no pre-built binaries for ${platformTag}.\n` +
      `[installer] Supported platforms: ${Object.keys(supported).join(", ")}.\n` +
      `[installer] To build from source: cargo build --workspace\n` +
      `[installer] Skipping smith-services install (non-fatal).`
    );
    return;
  }

  try {
    runCommand(smithRoot, { command: "npm", args: ["install", "-g", "@sibyllinesoft/smith-services"] });
  } catch {
    console.warn(
      `\n[installer] smith-services installation failed.\n` +
      `[installer] The platform package ${supported[platformTag]} may not be published yet.\n` +
      `[installer] This is non-fatal — you can build from source: cargo build --workspace\n` +
      `[installer] To retry later: npm install -g @sibyllinesoft/smith-services\n`
    );
    return;
  }

  // Verify at least one binary works
  try {
    execFileSync("smith-chat-daemon", ["--help"], { stdio: "pipe", env: process.env });
    console.log("[installer] smith-services installed and verified.");
  } catch {
    console.warn(
      `\n[installer] smith-services package installed but binaries not functional on ${platformTag}.\n` +
      `[installer] The platform package ${supported[platformTag]} may be missing from the registry.\n` +
      `[installer] This is non-fatal — you can build from source: cargo build --workspace\n`
    );
  }
}

function tryInstallAgentd(smithRoot: string): void {
  const platform = process.platform;
  const arch = process.arch;
  const platformTag = `${platform}-${arch}`;
  const supported: Record<string, string> = {
    "linux-x64": "@sibyllinesoft/agentd-linux-x64",
    "darwin-arm64": "@sibyllinesoft/agentd-darwin-arm64",
  };

  if (!supported[platformTag]) {
    console.warn(
      `[installer] agentd: no pre-built binary for ${platformTag}.\n` +
      `[installer] Supported platforms: ${Object.keys(supported).join(", ")}.\n` +
      `[installer] To use agentd on this platform, build from source (see the agentd repo).\n` +
      `[installer] Skipping agentd install (non-fatal).`
    );
    return;
  }

  try {
    runCommand(smithRoot, { command: "npm", args: ["install", "-g", "@sibyllinesoft/agentd"] });
  } catch {
    console.warn(
      `\n[installer] agentd installation failed.\n` +
      `[installer] The platform package ${supported[platformTag]} may not be published yet.\n` +
      `[installer] This is non-fatal — infrastructure and build steps are unaffected.\n` +
      `[installer] To resolve:\n` +
      `[installer]   - Retry later: npm install -g @sibyllinesoft/agentd\n` +
      `[installer]   - Or build from source (see the agentd repo)\n`
    );
    return;
  }

  // Verify the binary actually works (catches missing platform-specific package)
  try {
    execFileSync("agentd", ["--version"], { stdio: "pipe", env: process.env });
    console.log("[installer] agentd installed and verified.");
  } catch {
    console.warn(
      `\n[installer] agentd package installed but binary not functional on ${platformTag}.\n` +
      `[installer] The platform package ${supported[platformTag]} may be missing from the registry.\n` +
      `[installer] This is non-fatal — infrastructure and build steps are unaffected.\n` +
      `[installer] To resolve: build agentd from source (see the agentd repo).\n`
    );
  }
}

function waitForDockerHealth(smithRoot: string): void {
  console.log("[installer] Waiting for Docker services to become healthy...");
  try {
    execFileSync(
      "docker",
      ["compose", "up", "-d", "--wait", "--wait-timeout", "120"],
      { cwd: smithRoot, stdio: "inherit", env: process.env }
    );
    console.log("[installer] All Docker services healthy.");
  } catch {
    console.warn(
      "[installer] Some services may not have reached healthy state within timeout.\n" +
      "[installer] Check status with: docker compose ps\n" +
      "[installer] Check logs with: docker compose logs <service>"
    );
  }
}

function runOptionalTunnelE2E(smithRoot: string): void {
  const envPath = join(smithRoot, ".env");
  if (!existsSync(envPath)) {
    return;
  }

  const vars = parseEnvFile(envPath);
  const providers: string[] = [];
  const hasCloudflare =
    (vars.CLOUDFLARE_TUNNEL_E2E_URL ?? "").trim().length > 0 ||
    (vars.CLOUDFLARE_TUNNEL_HOSTNAME ?? "").trim().length > 0;
  const hasTailscale = (vars.TAILSCALE_TUNNEL_E2E_URL ?? "").trim().length > 0;

  if (hasCloudflare) {
    providers.push("cloudflare");
  }
  if (hasTailscale) {
    providers.push("tailscale");
  }

  if (providers.length === 0) {
    console.log(
      "[installer] Skipping tunnel e2e checks: no CLOUDFLARE/TAILSCALE tunnel e2e variables configured in .env"
    );
    return;
  }

  for (const provider of providers) {
    console.log(`[installer] Running tunnel e2e check for ${provider}`);
    runCommand(smithRoot, {
      command: "bash",
      args: ["scripts/tunnel-e2e.sh", provider],
    });
  }
}

function printSecurityWarnings(
  sourceFile: string | null,
  warnings: Array<{ message: string; recommendation: string }>
): void {
  if (warnings.length === 0) return;
  const sourceLabel = sourceFile ? ` (${sourceFile})` : "";
  console.error(`\n[SECURITY WARNING] Installer detected ${warnings.length} warning(s)${sourceLabel}`);
  for (const warning of warnings) {
    console.error(`[SECURITY WARNING] ${warning.message}`);
    console.error(`[SECURITY WARNING] Recommended action: ${warning.recommendation}`);
  }
  console.error(
    "[SECURITY WARNING] This installer will continue, but deployment outside a private network is not recommended."
  );
}

function runNonInteractiveBootstrap(
  smithRoot: string,
  step: string | undefined,
  force: boolean
): void {
  const normalizedStep = step?.toLowerCase() ?? "all";

  const plans: Record<string, CommandSpec[]> = {
    all: [
      { command: "bash", args: ["infra/envoy/certs/generate-certs.sh"] },
      { command: "docker", args: ["compose", "up", "-d"] },
      { command: "npm", args: ["install"] },
      { command: "npm", args: ["run", "build", "--workspaces", "--if-present"] },
    ],
    infra: [
      { command: "bash", args: ["infra/envoy/certs/generate-certs.sh"] },
      { command: "docker", args: ["compose", "up", "-d"] },
    ],
    build: [],
    npm: [
      { command: "npm", args: ["install"] },
    ],
    verify: [
      { command: "npm", args: ["run", "build", "--workspaces", "--if-present"] },
    ],
    "25": [
      { command: "npm", args: ["install"] },
    ],
    "30": [
      { command: "bash", args: ["infra/envoy/certs/generate-certs.sh"] },
      { command: "docker", args: ["compose", "up", "-d"] },
    ],
    "40": [],
    "90": [
      { command: "npm", args: ["run", "build", "--workspaces", "--if-present"] },
    ],
    "configure-policy": [
      { command: "docker", args: ["compose", "exec", "-T", "postgres", "psql", "-U", "smith", "-d", "smith", "-c", "SELECT id, name, updated_at FROM opa_policies ORDER BY updated_at DESC;"] },
      { command: "docker", args: ["compose", "exec", "-T", "opa-management", "wget", "-qO-", "http://localhost:8181/health"] },
    ],
    "policy": [
      { command: "docker", args: ["compose", "exec", "-T", "postgres", "psql", "-U", "smith", "-d", "smith", "-c", "SELECT id, name, updated_at FROM opa_policies ORDER BY updated_at DESC;"] },
      { command: "docker", args: ["compose", "exec", "-T", "opa-management", "wget", "-qO-", "http://localhost:8181/health"] },
    ],
  };

  const plan = plans[normalizedStep];
  if (!plan) {
    const valid = Object.keys(plans).join(", ");
    throw new Error(`Unknown --step '${step}'. Valid values: ${valid}`);
  }

  if (force && (normalizedStep === "all" || normalizedStep === "infra" || normalizedStep === "30")) {
    runCommand(smithRoot, { command: "docker", args: ["compose", "down"] });
  }

  for (const spec of plan) {
    runCommand(smithRoot, spec);
  }

  // Wait for Docker services to become healthy after infra steps
  const infraSteps = ["all", "infra", "30"];
  if (infraSteps.includes(normalizedStep)) {
    waitForDockerHealth(smithRoot);
  }

  // Install pre-built binaries (non-fatal) after build/all steps
  const binarySteps = ["all", "build", "40"];
  if (binarySteps.includes(normalizedStep)) {
    tryInstallSmithServices(smithRoot);
    tryInstallAgentd(smithRoot);
  }

  if (normalizedStep === "all" || normalizedStep === "verify" || normalizedStep === "90") {
    runOptionalTunnelE2E(smithRoot);
  }
}

function printHelp(): void {
  console.log(`smith-install — AI-guided Smith Core installer

Usage: smith-install [options]

Options:
  --non-interactive    Run bootstrap commands directly (no TUI)
  --provider <name>    LLM provider (default: anthropic)
  --model <id>         Model ID (default: claude-sonnet-4-20250514)
  --thinking <level>   Thinking level: none, low, medium, high (default: medium)
  --step <name>        Run one step: all, infra, build, npm, verify, policy (also 25/30/40/90)
  --force              Recreate infrastructure before running infra/all
  --repo <owner/repo>  GitHub repository (default: sibyllinesoft/smith-core)
  --ref <tag>          Release tag to install (default: latest)
  --help               Show this help`);
}

async function main(): Promise<void> {
  let args: CliArgs;
  try {
    args = parseArgs(process.argv);
  } catch (err) {
    console.error((err as Error).message);
    process.exit(1);
  }

  // Suppress pi-coding-agent update check (forked packages)
  process.env.PI_SKIP_VERSION_CHECK = "1";

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  await runPreflightChecks();

  // Resolve smith-core location
  const existingConfig = readSmithConfig();
  let smithRoot: string;

  if (args.repo) {
    smithRoot = resolve(args.repo);
  } else if (existingConfig && existsSync(existingConfig.installPath)) {
    smithRoot = existingConfig.installPath;
    console.log(`[installer] Smith Core ${existingConfig.ref} found at ${smithRoot}`);
  } else {
    const localRoot = findSmithRoot(process.cwd());
    if (localRoot) {
      smithRoot = localRoot;
    } else {
      const repo = args.repo ?? DEFAULT_REPO;
      const tag = args.ref ?? (await resolveLatestTag(repo));
      smithRoot = await downloadRepo(repo, tag);
      writeSmithConfig({
        version: tag.replace(/^v/, ""),
        repo,
        ref: tag,
        installPath: smithRoot,
        installedAt: new Date().toISOString(),
      });
    }
  }

  ensureEnvFile(smithRoot);
  ensureSecurityDefaults(smithRoot);
  ensureMacOsGondolinDefaults(smithRoot);

  const securityReport = evaluateInstallerSecurity(smithRoot);
  printSecurityWarnings(securityReport.sourceFile, securityReport.warnings);

  // Non-interactive mode: run bootstrap commands directly.
  if (args.nonInteractive) {
    try {
      runNonInteractiveBootstrap(smithRoot, args.step, args.force);
    } catch (e: unknown) {
      const err = e as { status?: number; message?: string };
      if (err.message) {
        console.error(err.message);
      }
      process.exit(err.status ?? 1);
    }
    return;
  }

  // Interactive mode: ensure API key is available, then create pi-agent session
  await ensureProviderApiKey(args.provider);

  const { InteractiveMode, runPrintMode } = await import(
    "@mariozechner/pi-coding-agent"
  );

  const { session } = await createInstallerSession({
    smithRoot,
    provider: args.provider,
    model: args.model,
    thinkingLevel: args.thinkingLevel,
    step: args.step,
    force: args.force,
    securityWarnings: securityReport.warnings.map(
      (w) => `${w.message} Recommended action: ${w.recommendation}`
    ),
  });

  const configSteps = ["configure-policy", "policy"];
  const isConfigStep = args.step && configSteps.includes(args.step.toLowerCase());

  const initialMessage = isConfigStep
    ? `Inspect and configure OPA security policies for this smith-core environment (step '${args.step}'). Show current policy state and tool-access rules.`
    : args.step
      ? `Bootstrap this smith-core environment and execute step '${args.step}'.`
      : "Bootstrap this smith-core development environment. Ensure Docker services are up, Rust workspaces build, Node workspaces are installed, and report any fixes required.";

  if (process.stdin.isTTY) {
    // Interactive TUI with auto-start prompt.
    const interactive = new InteractiveMode(session, { initialMessage });
    await interactive.run();
  } else {
    // Piped input: run with a default prompt.
    await runPrintMode(session, { mode: "text", initialMessage });
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
