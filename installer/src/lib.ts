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
  /** Path to smith repo root */
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
}

export interface Skill {
  name: string;
  description: string;
  content: string;
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
    if (existsSync(join(dir, "scripts", "bootstrap", "lib.sh"))) {
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
  let prompt = "You are the Smith platform installer agent.\n\n";
  prompt += `Smith repo root: ${opts.smithRoot}\n`;

  if (opts.step) {
    prompt += `\nThe user wants to run step ${opts.step} only.\n`;
  }
  if (opts.force) {
    prompt += "SMITH_FORCE=1 is set — re-run steps even if already done.\n";
  }

  return prompt;
}
