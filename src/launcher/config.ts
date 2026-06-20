/**
 * Launcher configuration: resolves paths and reads settings from the
 * environment and an optional `.env` file in the current working directory.
 */
import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, isAbsolute, resolve } from "node:path"
import { fileURLToPath } from "node:url"

export type HitlMode = "strict" | "guided" | "auto"
export type AuthMode = "mount" | "env"

export interface PurininaConfig {
  /** Root of the purinina repo (contains docker/Dockerfile and runtime/). */
  repoRoot: string
  /** Docker image tag to build/run. */
  image: string
  /** Container name. */
  container: string
  /** opencode version baked into the image at build time. */
  opencodeVersion: string
  /** Absolute path to the host engagement workspace (mounted into the sandbox). */
  workspace: string
  /** HITL policy mode passed into the sandbox. */
  hitl: HitlMode
  /** How model-provider credentials reach the sandbox. */
  authMode: AuthMode
  /** Absolute path to the host opencode auth.json (for authMode=mount). */
  hostAuthFile: string
  /** Optional default model (provider/model) passed to opencode. */
  model: string | undefined
}

/** Minimal `.env` parser — no dependency. Existing process.env always wins. */
function loadDotEnv(cwd: string): void {
  const file = resolve(cwd, ".env")
  if (!existsSync(file)) return
  for (const raw of readFileSync(file, "utf8").split("\n")) {
    const line = raw.trim()
    if (!line || line.startsWith("#")) continue
    const eq = line.indexOf("=")
    if (eq === -1) continue
    const key = line.slice(0, eq).trim()
    let val = line.slice(eq + 1).trim()
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1)
    }
    if (process.env[key] === undefined) process.env[key] = val
  }
}

function asHitl(v: string | undefined): HitlMode {
  return v === "guided" || v === "auto" ? v : "strict"
}

function resolveRepoRoot(): string {
  // dist/launcher/index.js OR src/launcher/index.ts -> repo root is two up.
  const here = dirname(fileURLToPath(import.meta.url))
  return resolve(here, "..", "..")
}

export function loadConfig(cwd: string = process.cwd()): PurininaConfig {
  loadDotEnv(cwd)

  const workspaceRaw = process.env.PURININA_WORKSPACE ?? "./engagement"
  const workspace = isAbsolute(workspaceRaw) ? workspaceRaw : resolve(cwd, workspaceRaw)

  return {
    repoRoot: resolveRepoRoot(),
    image: process.env.PURININA_IMAGE ?? "purinina:latest",
    container: process.env.PURININA_CONTAINER ?? "purinina-sandbox",
    opencodeVersion: process.env.OPENCODE_VERSION ?? "1.17.8",
    workspace,
    hitl: asHitl(process.env.PURININA_HITL),
    authMode: process.env.PURININA_AUTH_MODE === "env" ? "env" : "mount",
    hostAuthFile: resolve(homedir(), ".local/share/opencode/auth.json"),
    model: process.env.PURININA_MODEL || undefined,
  }
}
