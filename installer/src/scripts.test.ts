import { describe, it, expect } from "vitest";
import { existsSync } from "fs";
import { join } from "path";
import { findSmithRoot } from "./lib.js";

const smithRoot = findSmithRoot(process.cwd())!;

describe("smith-core bootstrap assets", () => {
  const requiredFiles = [
    "justfile",
    "docker-compose.yaml",
    "Cargo.toml",
    "package.json",
    "installer/agents.md",
  ];

  it.each(requiredFiles)("required file exists: %s", (relPath) => {
    expect(existsSync(join(smithRoot, relPath))).toBe(true);
  });
});
