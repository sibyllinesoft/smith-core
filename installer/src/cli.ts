#!/usr/bin/env node

import { existsSync } from "fs";
import { resolve, join } from "path";
import { execFileSync } from "child_process";
import { createInstallerSession } from "./agents.js";
import { parseArgs, findSmithRoot } from "./lib.js";
import type { CliArgs } from "./lib.js";

function printHelp(): void {
  console.log(`smith-install — AI-guided Smith platform installer

Usage: smith-install [options]

Options:
  --non-interactive    Run all steps without TUI (fallback to bootstrap.sh)
  --provider <name>    LLM provider (default: anthropic)
  --model <id>         Model ID (default: claude-sonnet-4-20250514)
  --thinking <level>   Thinking level: none, low, medium, high (default: medium)
  --step <prefix>      Run a single step only (e.g. 00, 30, 90)
  --force              Re-run all steps (ignore idempotency)
  --repo <path>        Path to smith repo root (auto-detected by default)
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

  // Resolve smith repo root
  const smithRoot = args.repo
    ? resolve(args.repo)
    : findSmithRoot(process.cwd());

  if (!smithRoot || !existsSync(join(smithRoot, "scripts", "bootstrap", "lib.sh"))) {
    console.error(
      "Error: Could not find Smith repo root.\n" +
      "Run from within the smith repo, or use --repo <path>.\n\n" +
      "To clone the repo:\n" +
      "  git clone https://github.com/nathanjhood/smith.git\n" +
      "  cd smith && npx @sibyllinesoft/smith-installer"
    );
    process.exit(1);
  }

  // Non-interactive mode: delegate to bootstrap.sh
  if (args.nonInteractive) {
    const bootstrapArgs: string[] = [];
    if (args.force) bootstrapArgs.push("--force");
    if (args.step) bootstrapArgs.push("--step", args.step);

    const bootstrapScript = join(smithRoot, "scripts", "bootstrap", "bootstrap.sh");
    try {
      execFileSync("bash", [bootstrapScript, ...bootstrapArgs], {
        cwd: smithRoot,
        stdio: "inherit",
        env: {
          ...process.env,
          ...(args.force ? { SMITH_FORCE: "1" } : {}),
        },
      });
    } catch (e: unknown) {
      const err = e as { status?: number };
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
  });

  const initialMessage = args.step
    ? `Run bootstrap step ${args.step} for this Smith development environment.`
    : "Bootstrap this Smith development environment. Run each step in order, diagnose any failures, and adapt to this system.";

  if (process.stdin.isTTY) {
    // Interactive TUI with auto-start prompt
    const interactive = new InteractiveMode(session, { initialMessage });
    await interactive.run();
  } else {
    // Piped input — run with a default prompt
    await runPrintMode(session, { mode: "text", initialMessage });
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
