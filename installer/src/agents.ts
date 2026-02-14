import {
  createAgentSession,
  DefaultResourceLoader,
  SessionManager,
  SettingsManager,
  AuthStorage,
  ModelRegistry,
  codingTools,
  type Skill as PiSkill,
} from "@mariozechner/pi-coding-agent";
import { getModel } from "@mariozechner/pi-ai";
import type { KnownProvider } from "@mariozechner/pi-ai";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { loadSkills, buildSystemPrompt } from "./lib.js";
import type { InstallerOptions } from "./lib.js";

export type { InstallerOptions };

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(__dirname, "..");

export async function createInstallerSession(opts: InstallerOptions) {
  const authStorage = new AuthStorage();
  const modelRegistry = new ModelRegistry(authStorage);

  const agentsMd = readFileSync(join(PKG_ROOT, "agents.md"), "utf8");
  const installerSkills = loadSkills(join(PKG_ROOT, "skills"));

  const loader = new DefaultResourceLoader({
    cwd: opts.smithRoot,
    systemPromptOverride: () => buildSystemPrompt(opts),
    agentsFilesOverride: (current) => ({
      agentsFiles: [
        ...current.agentsFiles,
        { path: "/smith-installer/AGENTS.md", content: agentsMd },
      ],
    }),
    skillsOverride: (current) => ({
      skills: [
        ...current.skills,
        ...installerSkills.map((s): PiSkill => ({
          name: s.name,
          description: s.description,
          filePath: join(PKG_ROOT, "skills", s.name, "SKILL.md"),
          baseDir: join(PKG_ROOT, "skills", s.name),
          source: s.content,
          disableModelInvocation: false,
        })),
      ],
      diagnostics: current.diagnostics,
    }),
  });
  await loader.reload();

  const provider = opts.provider ?? ("anthropic" as const);
  const modelId = opts.model ?? "claude-sonnet-4-20250514";

  const { session } = await createAgentSession({
    cwd: opts.smithRoot,
    model: (getModel as Function)(provider, modelId),
    thinkingLevel: opts.thinkingLevel ?? "medium",
    authStorage,
    modelRegistry,
    tools: codingTools,
    resourceLoader: loader,
    sessionManager: SessionManager.create(opts.smithRoot),
    settingsManager: SettingsManager.inMemory({
      compaction: { enabled: true },
    }),
  });

  return { session, authStorage, modelRegistry };
}
