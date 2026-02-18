#!/usr/bin/env node

import { copyFileSync, existsSync, readFileSync, writeFileSync } from "fs";
import { resolve, join } from "path";
import { execFileSync } from "child_process";
import { createInstallerSession } from "./agents.js";
import { parseArgs, findSmithRoot, evaluateInstallerSecurity } from "./lib.js";
import type { CliArgs } from "./lib.js";

type CommandSpec = {
  command: string;
  args: string[];
};

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

  try {
    execFileSync("gondolin", ["help"], { stdio: "ignore", env: process.env });
  } catch {
    throw new Error(
      "macOS setup requires 'gondolin' for sandboxed VM execution. Install Gondolin and rerun the installer."
    );
  }

  upsertEnvValue(envPath, "SMITH_EXECUTOR_VM_POOL_ENABLED", "true");
  upsertEnvValue(envPath, "SMITH_EXECUTOR_VM_METHOD", "gondolin");
  upsertEnvValue(envPath, "SMITH_EXECUTOR_GONDOLIN_COMMAND", "gondolin");
  upsertEnvValue(envPath, "SMITH_EXECUTOR_GONDOLIN_ARGS", "exec,--");

  console.log(
    "[installer] macOS detected: enabled persistent VM pool and Gondolin defaults in .env"
  );
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
      { command: "docker", args: ["compose", "ps"] },
      { command: "cargo", args: ["build", "--workspace"] },
      { command: "cargo", args: ["build", "--manifest-path", "agent/agentd/Cargo.toml", "--features", "grpc", "--bin", "agentd"] },
      { command: "npm", args: ["install"] },
      { command: "cargo", args: ["check", "--workspace"] },
      { command: "cargo", args: ["check", "--manifest-path", "agent/agentd/Cargo.toml", "--features", "grpc", "--bin", "agentd"] },
      { command: "npm", args: ["run", "build", "--workspaces", "--if-present"] },
    ],
    infra: [
      { command: "bash", args: ["infra/envoy/certs/generate-certs.sh"] },
      { command: "docker", args: ["compose", "up", "-d"] },
      { command: "docker", args: ["compose", "ps"] },
    ],
    build: [
      { command: "cargo", args: ["build", "--workspace"] },
      { command: "cargo", args: ["build", "--manifest-path", "agent/agentd/Cargo.toml", "--features", "grpc", "--bin", "agentd"] },
    ],
    npm: [
      { command: "npm", args: ["install"] },
    ],
    verify: [
      { command: "cargo", args: ["check", "--workspace"] },
      { command: "cargo", args: ["check", "--manifest-path", "agent/agentd/Cargo.toml", "--features", "grpc", "--bin", "agentd"] },
      { command: "npm", args: ["run", "build", "--workspaces", "--if-present"] },
    ],
    "25": [
      { command: "npm", args: ["install"] },
    ],
    "30": [
      { command: "bash", args: ["infra/envoy/certs/generate-certs.sh"] },
      { command: "docker", args: ["compose", "up", "-d"] },
      { command: "docker", args: ["compose", "ps"] },
    ],
    "40": [
      { command: "cargo", args: ["build", "--workspace"] },
      { command: "cargo", args: ["build", "--manifest-path", "agent/agentd/Cargo.toml", "--features", "grpc", "--bin", "agentd"] },
    ],
    "90": [
      { command: "cargo", args: ["check", "--workspace"] },
      { command: "cargo", args: ["check", "--manifest-path", "agent/agentd/Cargo.toml", "--features", "grpc", "--bin", "agentd"] },
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
  --step <name>        Run one step: all, infra, build, npm, verify, policy (also accepts 25/30/40/90)
  --force              Recreate infrastructure before running infra/all
  --repo <path>        Path to smith-core repo root (auto-detected by default)
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

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  // Resolve smith-core repo root.
  const smithRoot = args.repo
    ? resolve(args.repo)
    : findSmithRoot(process.cwd());

  if (!smithRoot || !existsSync(join(smithRoot, "justfile"))) {
    console.error(
      "Error: Could not find Smith Core repo root.\n" +
      "Run from within the smith-core repo, or use --repo <path>.\n\n" +
      "To clone the repo:\n" +
      "  git clone https://github.com/sibyllinesoft/smith-core.git\n" +
      "  cd smith-core && npx @sibyllinesoft/smith-installer"
    );
    process.exit(1);
  }

  ensureEnvFile(smithRoot);
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

  // Interactive mode: create pi-agent session
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
