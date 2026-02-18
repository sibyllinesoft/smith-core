import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { findSmithRoot } from "./lib.js";

const smithRoot = findSmithRoot(process.cwd())!;
const pkgDir = join(smithRoot, "installer");

describe("package.json manifest", () => {
  const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));

  it("has correct package name", () => {
    expect(pkg.name).toBe("@sibyllinesoft/smith-installer");
  });

  it("has bin entry", () => {
    expect(pkg.bin).toBeDefined();
    expect(pkg.bin["smith-install"]).toBe("./dist/cli.js");
  });

  it("has main entry", () => {
    expect(pkg.main).toBe("./dist/index.js");
  });

  it("has types entry", () => {
    expect(pkg.types).toBe("./dist/index.d.ts");
  });

  it("has exports map", () => {
    expect(pkg.exports["."]).toBeDefined();
    expect(pkg.exports["."].import).toBe("./dist/index.js");
    expect(pkg.exports["."].types).toBe("./dist/index.d.ts");
  });

  it("has files array including dist, agents.md, and skills", () => {
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("agents.md");
    expect(pkg.files).toContain("skills");
  });

  it("type is module", () => {
    expect(pkg.type).toBe("module");
  });

  it("engines requires node >= 22", () => {
    expect(pkg.engines).toBeDefined();
    expect(pkg.engines.node).toMatch(/>=\s*22/);
  });
});

describe("agents.md", () => {
  const agentsMd = readFileSync(join(pkgDir, "agents.md"), "utf8");
  const lines = agentsMd.split("\n");

  it("exists and has at least 30 lines", () => {
    expect(lines.length).toBeGreaterThanOrEqual(30);
  });

  it("has key headings", () => {
    expect(agentsMd).toContain("# Smith Core Installer & Configuration Agent");
    expect(agentsMd).toContain("## Principles");
    expect(agentsMd).toContain("## Workflow");
  });

  it("references bootstrap commands used in this repo", () => {
    expect(agentsMd).toContain("docker compose up -d");
    expect(agentsMd).toContain("cargo build --workspace");
    expect(agentsMd).toContain("npm install");
  });
});
