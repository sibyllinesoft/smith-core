import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { findSmithRoot } from "./lib.js";

const smithRoot = findSmithRoot(process.cwd())!;
const pkgDir = join(smithRoot, "packages", "smith-installer");

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

  it("has files array including dist, agents.md, skills", () => {
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("agents.md");
    expect(pkg.files).toContain("skills");
  });

  it("type is module", () => {
    expect(pkg.type).toBe("module");
  });

  it("engines requires node >= 20", () => {
    expect(pkg.engines).toBeDefined();
    expect(pkg.engines.node).toMatch(/>=\s*20/);
  });
});

describe("agents.md", () => {
  const agentsMd = readFileSync(join(pkgDir, "agents.md"), "utf8");
  const lines = agentsMd.split("\n");

  it("exists and has at least 50 lines", () => {
    expect(lines.length).toBeGreaterThanOrEqual(50);
  });

  it("has key headings", () => {
    expect(agentsMd).toContain("# Smith Installer Agent");
    expect(agentsMd).toContain("## Principles");
    expect(agentsMd).toContain("## Workflow Overview");
  });

  const stepPrefixes = ["00", "10", "20", "25", "30", "35", "40", "50", "60", "90"];

  it.each(stepPrefixes)("references step %s script", (prefix) => {
    const pattern = new RegExp(`${prefix}-[a-z-]+\\.sh`);
    expect(agentsMd, `agents.md missing step ${prefix}`).toMatch(pattern);
  });
});
