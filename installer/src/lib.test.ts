import { describe, it, expect } from "vitest";
import { join } from "path";
import { parseArgs, findSmithRoot, buildSystemPrompt, loadSkills } from "./lib.js";
import type { InstallerOptions } from "./lib.js";

// Helper: build argv with node + script prefix
const argv = (...flags: string[]) => ["node", "smith-install", ...flags];

// ── parseArgs ────────────────────────────────────────────────────────

describe("parseArgs", () => {
  it("returns defaults with no args", () => {
    const args = parseArgs(argv());
    expect(args).toEqual({
      nonInteractive: false,
      provider: "anthropic",
      model: "claude-sonnet-4-20250514",
      thinkingLevel: "medium",
      force: false,
      help: false,
    });
  });

  it("sets --non-interactive flag", () => {
    expect(parseArgs(argv("--non-interactive")).nonInteractive).toBe(true);
  });

  it("sets --force flag", () => {
    expect(parseArgs(argv("--force")).force).toBe(true);
  });

  it("sets --help flag", () => {
    expect(parseArgs(argv("--help")).help).toBe(true);
  });

  it("sets -h flag", () => {
    expect(parseArgs(argv("-h")).help).toBe(true);
  });

  it("parses --provider value", () => {
    expect(parseArgs(argv("--provider", "openai")).provider).toBe("openai");
  });

  it("parses --model value", () => {
    expect(parseArgs(argv("--model", "gpt-4")).model).toBe("gpt-4");
  });

  it("parses --thinking value", () => {
    expect(parseArgs(argv("--thinking", "high")).thinkingLevel).toBe("high");
  });

  it("parses --step value", () => {
    expect(parseArgs(argv("--step", "30")).step).toBe("30");
  });

  it("parses --repo value", () => {
    expect(parseArgs(argv("--repo", "/tmp/smith")).repo).toBe("/tmp/smith");
  });

  it("handles combined flags", () => {
    const args = parseArgs(argv("--force", "--non-interactive", "--step", "90", "--provider", "local"));
    expect(args.force).toBe(true);
    expect(args.nonInteractive).toBe(true);
    expect(args.step).toBe("90");
    expect(args.provider).toBe("local");
  });

  it("throws on unknown option", () => {
    expect(() => parseArgs(argv("--banana"))).toThrow("Unknown option: --banana");
  });

  it("ignores argv[0] and argv[1]", () => {
    const args = parseArgs(["/usr/bin/node", "/path/to/cli.js", "--force"]);
    expect(args.force).toBe(true);
  });
});

// ── findSmithRoot ────────────────────────────────────────────────────

describe("findSmithRoot", () => {
  // We're running inside the smith repo, so cwd should resolve
  const smithRoot = findSmithRoot(process.cwd());

  it("finds repo from cwd (inside smith)", () => {
    expect(smithRoot).not.toBeNull();
    expect(smithRoot).toMatch(/smith$/);
  });

  it("finds repo from nested directory", () => {
    const nested = join(smithRoot!, "packages", "smith-installer", "src");
    expect(findSmithRoot(nested)).toBe(smithRoot);
  });

  it("returns null from /tmp", () => {
    expect(findSmithRoot("/tmp")).toBeNull();
  });

  it("returns null from /", () => {
    expect(findSmithRoot("/")).toBeNull();
  });
});

// ── buildSystemPrompt ────────────────────────────────────────────────

describe("buildSystemPrompt", () => {
  const base: InstallerOptions = { smithRoot: "/home/user/smith" };

  it("includes smithRoot and agent identity", () => {
    const prompt = buildSystemPrompt(base);
    expect(prompt).toContain("Smith platform installer agent");
    expect(prompt).toContain("/home/user/smith");
  });

  it("includes step reference when step is set", () => {
    const prompt = buildSystemPrompt({ ...base, step: "30" });
    expect(prompt).toContain("step 30");
  });

  it("includes SMITH_FORCE when force is set", () => {
    const prompt = buildSystemPrompt({ ...base, force: true });
    expect(prompt).toContain("SMITH_FORCE=1");
  });

  it("includes both step and force", () => {
    const prompt = buildSystemPrompt({ ...base, step: "00", force: true });
    expect(prompt).toContain("step 00");
    expect(prompt).toContain("SMITH_FORCE=1");
  });

  it("does not include step/force text when not set", () => {
    const prompt = buildSystemPrompt(base);
    expect(prompt).not.toContain("step");
    expect(prompt).not.toContain("SMITH_FORCE");
  });
});

// ── loadSkills ───────────────────────────────────────────────────────

describe("loadSkills", () => {
  const smithRoot = findSmithRoot(process.cwd())!;
  const skillsDir = join(smithRoot, "packages", "smith-installer", "skills");

  const EXPECTED_SKILLS = [
    "build-client",
    "configure-agentd",
    "detect-system",
    "generate-certs",
    "install-agentd",
    "install-runtime",
    "setup-activitywatch",
    "start-agentd",
    "start-stack",
    "verify",
  ];

  it("loads all 10 skills from the real skills directory", () => {
    const skills = loadSkills(skillsDir);
    expect(skills).toHaveLength(10);
  });

  it("each skill has non-empty name, description, content", () => {
    const skills = loadSkills(skillsDir);
    for (const skill of skills) {
      expect(skill.name).toBeTruthy();
      expect(skill.description).toBeTruthy();
      expect(skill.content).toBeTruthy();
    }
  });

  it("skill names match expected directory names", () => {
    const skills = loadSkills(skillsDir);
    const names = skills.map((s) => s.name).sort();
    expect(names).toEqual(EXPECTED_SKILLS);
  });

  it("descriptions are extracted from frontmatter (differ from dir name)", () => {
    const skills = loadSkills(skillsDir);
    for (const skill of skills) {
      expect(skill.description).not.toBe(skill.name);
      expect(skill.description.length).toBeGreaterThan(10);
    }
  });

  it("content includes 'What It Does' section", () => {
    const skills = loadSkills(skillsDir);
    for (const skill of skills) {
      expect(skill.content).toContain("What It Does");
    }
  });

  it("returns empty array for nonexistent directory", () => {
    expect(loadSkills("/tmp/nonexistent-skills-dir-xyz")).toEqual([]);
  });

  it("returns empty array for directory with no SKILL.md files", () => {
    expect(loadSkills("/tmp")).toEqual([]);
  });
});
