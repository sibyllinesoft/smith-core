import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";
import { findSmithRoot } from "./lib.js";

const smithRoot = findSmithRoot(process.cwd())!;
const skillsDir = join(smithRoot, "installer", "skills");
const skillDirs = readdirSync(skillsDir).filter((e) =>
  statSync(join(skillsDir, e)).isDirectory()
);

describe("SKILL.md structural validation", () => {
  it("exactly 16 skill directories exist", () => {
    expect(skillDirs).toHaveLength(16);
  });

  it("every directory has a SKILL.md", () => {
    for (const dir of skillDirs) {
      const skillFile = join(skillsDir, dir, "SKILL.md");
      expect(() => readFileSync(skillFile, "utf8")).not.toThrow();
    }
  });

  it("every SKILL.md has valid YAML frontmatter", () => {
    const frontmatterRe = /^---\s*\ndescription:\s*(.+)\n---/;
    for (const dir of skillDirs) {
      const content = readFileSync(join(skillsDir, dir, "SKILL.md"), "utf8");
      expect(content).toMatch(frontmatterRe);
    }
  });

  it("descriptions are non-trivial (length > 10)", () => {
    const frontmatterRe = /^---\s*\ndescription:\s*(.+)\n---/;
    for (const dir of skillDirs) {
      const content = readFileSync(join(skillsDir, dir, "SKILL.md"), "utf8");
      const match = content.match(frontmatterRe);
      expect(match![1]!.length).toBeGreaterThan(10);
    }
  });

  it.each(["What It Does", "Prerequisites", "Expected Output", "Common Failures"])(
    "every SKILL.md has required section: %s",
    (section) => {
      for (const dir of skillDirs) {
        const content = readFileSync(join(skillsDir, dir, "SKILL.md"), "utf8");
        expect(content, `${dir}/SKILL.md missing "${section}"`).toContain(section);
      }
    }
  );

  it("no SKILL.md is trivially short (>= 40 lines)", () => {
    for (const dir of skillDirs) {
      const content = readFileSync(join(skillsDir, dir, "SKILL.md"), "utf8");
      const lines = content.split("\n").length;
      expect(lines, `${dir}/SKILL.md has only ${lines} lines`).toBeGreaterThanOrEqual(40);
    }
  });

  it("directory names are kebab-case", () => {
    const kebab = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
    for (const dir of skillDirs) {
      expect(dir, `${dir} is not kebab-case`).toMatch(kebab);
    }
  });
});
