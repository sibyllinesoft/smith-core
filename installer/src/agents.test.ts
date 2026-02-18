import { describe, it, expect } from "vitest";
import { createInstallerSession } from "./agents.js";
import { findSmithRoot } from "./lib.js";

describe("createInstallerSession", () => {
  it("loads installer skills into the resource loader", async () => {
    const smithRoot = findSmithRoot(process.cwd());
    expect(smithRoot).not.toBeNull();

    const { session } = await createInstallerSession({ smithRoot: smithRoot! });
    const loader = (session as unknown as { _resourceLoader: { getSkills: () => { skills: Array<{ name: string; filePath: string }> } } })._resourceLoader;
    const skills = loader
      .getSkills()
      .skills
      .filter((s) => s.filePath.includes("/installer/skills/"));

    expect(skills).toHaveLength(16);
    expect(skills.map((s) => s.name).sort()).toEqual([
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
    ]);
  });
});
