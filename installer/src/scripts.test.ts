import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import { join } from "path";
import { findSmithRoot } from "./lib.js";

const smithRoot = findSmithRoot(process.cwd())!;
const bootstrapDir = join(smithRoot, "scripts", "bootstrap");
const stepsDir = join(bootstrapDir, "steps");

function bashSyntaxCheck(scriptPath: string): void {
  execFileSync("bash", ["-n", scriptPath], { stdio: "pipe" });
}

describe("shell script syntax (bash -n)", () => {
  const topLevelScripts = [
    "bootstrap.sh",
    "lib.sh",
    "secure.sh",
    "yolo.sh",
  ];

  it.each(topLevelScripts)("scripts/bootstrap/%s parses cleanly", (script) => {
    expect(() => bashSyntaxCheck(join(bootstrapDir, script))).not.toThrow();
  });

  const stepScripts = [
    "00-detect-system.sh",
    "10-install-runtime.sh",
    "20-generate-certs.sh",
    "25-build-client.sh",
    "30-start-stack.sh",
    "35-setup-activitywatch.sh",
    "40-install-agentd.sh",
    "50-configure-agentd.sh",
    "60-start-agentd.sh",
    "90-verify.sh",
  ];

  it.each(stepScripts)("scripts/bootstrap/steps/%s parses cleanly", (script) => {
    expect(() => bashSyntaxCheck(join(stepsDir, script))).not.toThrow();
  });
});

describe("install.sh syntax", () => {
  it("install.sh at repo root parses cleanly", () => {
    expect(() => bashSyntaxCheck(join(smithRoot, "install.sh"))).not.toThrow();
  });
});
