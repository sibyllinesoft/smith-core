import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  parseArgs,
  findSmithRoot,
  buildSystemPrompt,
  loadSkills,
  evaluateInstallerSecurity,
} from "./lib.js";
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
      model: "claude-sonnet-4-5-20250929",
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
  // We're running inside the smith-core repo, so cwd should resolve.
  const smithRoot = findSmithRoot(process.cwd());

  it("finds repo from cwd (inside smith-core)", () => {
    expect(smithRoot).not.toBeNull();
    expect(smithRoot).toMatch(/smith-core$/);
  });

  it("finds repo from nested directory", () => {
    const nested = join(smithRoot!, "installer", "src");
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
  const base: InstallerOptions = { smithRoot: "/home/user/smith-core" };

  it("includes smithRoot and agent identity", () => {
    const prompt = buildSystemPrompt(base);
    expect(prompt).toContain("Smith Core installer and configuration agent");
    expect(prompt).toContain("/home/user/smith-core");
  });

  it("includes step reference when step is set", () => {
    const prompt = buildSystemPrompt({ ...base, step: "30" });
    expect(prompt).toContain("installer step '30'");
  });

  it("includes force guidance when force is set", () => {
    const prompt = buildSystemPrompt({ ...base, force: true });
    expect(prompt).toContain("--force is set");
  });

  it("includes both step and force", () => {
    const prompt = buildSystemPrompt({ ...base, step: "00", force: true });
    expect(prompt).toContain("installer step '00'");
    expect(prompt).toContain("--force is set");
  });

  it("does not include step/force text when not set", () => {
    const prompt = buildSystemPrompt(base);
    expect(prompt).not.toContain("step");
    expect(prompt).not.toContain("--force is set");
  });

  it("includes configuration mode text for policy step", () => {
    const prompt = buildSystemPrompt({ ...base, step: "policy" });
    expect(prompt).toContain("configuration mode");
    expect(prompt).toContain("policy system");
  });

  it("includes configuration mode text for configure-policy step", () => {
    const prompt = buildSystemPrompt({ ...base, step: "configure-policy" });
    expect(prompt).toContain("configuration mode");
  });

  it("includes explicit security warnings when provided", () => {
    const prompt = buildSystemPrompt({
      ...base,
      securityWarnings: [
        "POSTGRES_PASSWORD is weak.",
        "No Cloudflare Tunnel or Tailscale indicators found.",
      ],
    });
    expect(prompt).toContain("Local security posture warnings were detected");
    expect(prompt).toContain("POSTGRES_PASSWORD is weak.");
    expect(prompt).toContain("Cloudflare Tunnel or Tailscale");
  });
});

// ── evaluateInstallerSecurity ─────────────────────────────────────────

describe("evaluateInstallerSecurity", () => {
  it("flags weak defaults and missing private-network indicators", () => {
    const root = mkdtempSync(join(tmpdir(), "smith-installer-sec-"));
    writeFileSync(
      join(root, ".env.example"),
      [
        "POSTGRES_PASSWORD=smith-dev",
        "CLICKHOUSE_PASSWORD=observability-dev",
        "GRAFANA_ADMIN_PASSWORD=admin",
        "MCP_INDEX_API_TOKEN=",
        "AGENTD_CAPABILITY_DIGEST=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      ].join("\n")
    );

    const report = evaluateInstallerSecurity(root);
    const ids = report.warnings.map((w) => w.id);
    expect(ids).toContain("weak-postgres_password");
    expect(ids).toContain("weak-clickhouse_password");
    expect(ids).toContain("weak-grafana_admin_password");
    expect(ids).toContain("weak-mcp-index-token");
    expect(ids).toContain("missing-private-network-indicator");

    rmSync(root, { recursive: true, force: true });
  });

  it("prefers .env over .env.example and suppresses warnings for strong values", () => {
    const root = mkdtempSync(join(tmpdir(), "smith-installer-sec-"));
    mkdirSync(root, { recursive: true });
    writeFileSync(join(root, ".env.example"), "POSTGRES_PASSWORD=smith-dev\n");
    writeFileSync(
      join(root, ".env"),
      [
        "POSTGRES_PASSWORD=SuperLongUniqueSecretValue123!",
        "CLICKHOUSE_PASSWORD=AnotherLongSecretValue456!",
        "GRAFANA_ADMIN_PASSWORD=DifferentLongSecret789!",
        "MCP_INDEX_API_TOKEN=very-long-random-token-value-123456",
        "MCP_SIDECAR_API_TOKEN=very-long-random-sidecar-token-value-123456",
        "CHAT_BRIDGE_ADMIN_TOKEN=very-long-random-chat-admin-token-value-123456",
        "AGENTD_CAPABILITY_DIGEST=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "CLOUDFLARE_TUNNEL_TOKEN=test-tunnel-token",
      ].join("\n")
    );

    const report = evaluateInstallerSecurity(root);
    expect(report.sourceFile).toBe(join(root, ".env"));
    expect(report.warnings.find((w) => w.id.startsWith("weak-"))).toBeUndefined();
    expect(
      report.warnings.find((w) => w.id === "missing-private-network-indicator")
    ).toBeUndefined();

    rmSync(root, { recursive: true, force: true });
  });

  it("accepts hostname/url indicators for private-network hints", () => {
    const root = mkdtempSync(join(tmpdir(), "smith-installer-sec-"));
    writeFileSync(
      join(root, ".env"),
      [
        "POSTGRES_PASSWORD=good-secret-1",
        "CLICKHOUSE_PASSWORD=good-secret-2",
        "GRAFANA_ADMIN_PASSWORD=good-secret-3",
        "MCP_INDEX_API_TOKEN=long-token-1234567890",
        "MCP_SIDECAR_API_TOKEN=long-sidecar-token-1234567890",
        "CHAT_BRIDGE_ADMIN_TOKEN=long-chat-admin-token-1234567890",
        "AGENTD_CAPABILITY_DIGEST=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "CLOUDFLARE_TUNNEL_HOSTNAME=agent.example.com",
        "TAILSCALE_TUNNEL_E2E_URL=https://smith-core.tailnet.ts.net/health",
      ].join("\n")
    );

    const report = evaluateInstallerSecurity(root);
    expect(
      report.warnings.find((w) => w.id === "missing-private-network-indicator")
    ).toBeUndefined();

    rmSync(root, { recursive: true, force: true });
  });

  it("warns when AGENTD_GRPC_LISTEN is non-loopback", () => {
    const root = mkdtempSync(join(tmpdir(), "smith-installer-sec-"));
    writeFileSync(
      join(root, ".env"),
      [
        "POSTGRES_PASSWORD=good-secret-1",
        "CLICKHOUSE_PASSWORD=good-secret-2",
        "GRAFANA_ADMIN_PASSWORD=good-secret-3",
        "MCP_INDEX_API_TOKEN=long-token-1234567890",
        "MCP_SIDECAR_API_TOKEN=long-sidecar-token-1234567890",
        "CHAT_BRIDGE_ADMIN_TOKEN=long-chat-admin-token-1234567890",
        "AGENTD_CAPABILITY_DIGEST=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "TAILSCALE_AUTHKEY=tskey-abc",
        "AGENTD_GRPC_LISTEN=0.0.0.0:9500",
      ].join("\n")
    );

    const report = evaluateInstallerSecurity(root);
    expect(report.warnings.map((w) => w.id)).toContain("agentd-grpc-non-loopback");

    rmSync(root, { recursive: true, force: true });
  });
});

// ── loadSkills ───────────────────────────────────────────────────────

describe("loadSkills", () => {
  const smithRoot = findSmithRoot(process.cwd())!;
  const skillsDir = join(smithRoot, "installer", "skills");

  const EXPECTED_SKILLS = [
    "build-client",
    "choose-deployment",
    "configure-agentd",
    "configure-policy",
    "detect-system",
    "generate-certs",
    "generate-pairing-code",
    "install-agentd",
    "install-runtime",
    "preflight",
    "setup-activitywatch",
    "setup-chat-bridge",
    "start-agentd",
    "start-chat-bridge",
    "start-stack",
    "verify",
  ];

  it("loads all skills from the real skills directory", () => {
    const skills = loadSkills(skillsDir);
    expect(skills).toHaveLength(16);
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
