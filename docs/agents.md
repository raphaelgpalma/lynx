# Agents

Purinina's v1 ships four agents. Each is an opencode agent defined in
`runtime/agent/*.md` (frontmatter for config, body for the system prompt).
"Tool categories" — CAI's idea that a recon agent shouldn't exploit — are
expressed with **per-agent permissions**.

## The line-up

| Agent            | Mode     | Role                                                                                                         | Tool scope                                           |
| ---------------- | -------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| **orchestrator** | primary  | Plans the engagement, delegates to specialists via `task`, synthesizes results, keeps the operator informed. | `task` (delegate), light `bash`/`edit` (HITL-gated)  |
| **recon**        | subagent | Host/port/service/DNS/web discovery and enumeration. Maps the attack surface; never exploits.                | recon + readonly bash; **exploitation tools denied** |
| **web-exploit**  | subagent | Web/API testing and authorized exploitation; builds PoCs.                                                    | full bash + edit, all HITL-gated; no DoS             |
| **reporter**     | subagent | Turns findings into `reports/REPORT.md`.                                                                     | **no bash**; `edit` only                             |

## How delegation works

The orchestrator is the primary agent you talk to. It can delegate two ways:

- **Single hand-off** — opencode's built-in `task` tool (the idiomatic
  equivalent of CAI's `handoff` / `transfer_to_X`).
- **Structured multi-agent coordination** — the Purinina **pattern engine**
  (Phase 2), exposed as orchestrator-only tools:

```
operator → orchestrator
   ├── purinina_parallel([{recon, host A}, {recon, host B}, {recon, host C}])  # fan-out, concurrent
   ├── purinina_pipeline(["recon","web-exploit","reporter"], input)            # assembly line
   └── purinina_swarm(entry="recon", input="own the box")                      # peer-to-peer hand-offs
```

The engine drives each agent via the opencode SDK (its own session per agent),
still under the HITL gate, using each agent's configured model. In a swarm, an
agent hands off by ending its reply with `HANDOFF: <agent> — <task>` (or `DONE`).
See [architecture.md](./architecture.md) for the full design, bounds, and the
remaining patterns on the roadmap (conditional, hierarchical, `purinina.yml`).

## Choosing a model per agent

You can assign any model accessible through opencode to each agent individually
(the analogue of CAI's `CAI_<AGENT>_MODEL`). For example: a big model for
`web-exploit`, a fast/cheap one for `recon`, a writing-focused one for
`reporter`.

```bash
purinina models          # interactive: pick a model for the default + each agent
purinina models list     # print every model accessible through opencode
purinina status          # show the current per-agent assignment
```

How it works (no image rebuild needed):

- Choices are saved to `purinina.models.json` next to where you run the launcher:
  ```json
  {
    "default": "ollama-cloud/qwen3-coder:480b",
    "agents": {
      "recon": "ollama-cloud/gpt-oss:20b",
      "web-exploit": "ollama-cloud/deepseek-v3.1:671b",
      "reporter": "ollama-cloud/gpt-oss:120b"
    }
  }
  ```
- On launch, the launcher merges these into `<workspace>/opencode.json` as the
  top-level `model` (default + fallback) and `agent.<name>.model` per agent.
  opencode deep-merges this project config over the global one, so the per-agent
  models apply while the Purinina plugin, permissions and agents keep working.
- An agent without an explicit choice uses the default. You can also hand-edit
  `purinina.models.json` (or the workspace `opencode.json`) directly.

## Per-agent tool categories (example)

`recon` is restricted from exploitation by denying those binaries in its
frontmatter, while leaving recon/readonly commands to the global HITL gate:

```yaml
permission:
  bash:
    "*": ask # everything still goes through the HITL policy
    "sqlmap*": deny # …but exploitation tools are off-limits for recon
    "hydra*": deny
    "nc*": deny
  edit: allow
```

`reporter` has no shell at all:

```yaml
tools:
  bash: false
permission:
  edit: allow
  bash: deny
```

## Global rules

Every agent also reads the workspace `AGENTS.md` (auto-loaded by opencode), which
enforces: confirm scope first, respect HITL, stay inside the workspace, and log
findings with `purinina_note`. See `runtime/workspace-skeleton/AGENTS.md`.

## Engagement tools (from the plugin)

- **`purinina_scope`** — read `scope/SCOPE.md`; agents call it before intrusive
  actions to confirm authorization.
- **`purinina_note`** — append a timestamped, phase-tagged entry to
  `notes/engagement-log.md`; the reporter builds the deliverable from this trail.

## Adding an agent

1. Create `runtime/agent/<name>.md` with frontmatter (`description`, `mode`,
   `permission`, optional `model`/`temperature`) and a system-prompt body.
2. Constrain its tool category via `permission.bash` patterns.
3. Mention it in the orchestrator's delegation list so it gets used.
4. Rebuild the image (`purinina build`).
