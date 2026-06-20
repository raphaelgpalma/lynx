# Agents

Purinina's v1 ships four agents. Each is an opencode agent defined in
`runtime/agent/*.md` (frontmatter for config, body for the system prompt).
"Tool categories" — CAI's idea that a recon agent shouldn't exploit — are
expressed with **per-agent permissions**.

## The line-up

| Agent | Mode | Role | Tool scope |
| --- | --- | --- | --- |
| **orchestrator** | primary | Plans the engagement, delegates to specialists via `task`, synthesizes results, keeps the operator informed. | `task` (delegate), light `bash`/`edit` (HITL-gated) |
| **recon** | subagent | Host/port/service/DNS/web discovery and enumeration. Maps the attack surface; never exploits. | recon + readonly bash; **exploitation tools denied** |
| **web-exploit** | subagent | Web/API testing and authorized exploitation; builds PoCs. | full bash + edit, all HITL-gated; no DoS |
| **reporter** | subagent | Turns findings into `reports/REPORT.md`. | **no bash**; `edit` only |

## How delegation works (Phase 1)

The orchestrator is the primary agent you talk to. It uses opencode's built-in
`task` tool to spin up specialist subagents — Purinina's idiomatic equivalent of
CAI's `handoff` / `transfer_to_X`. A typical flow:

```
operator → orchestrator
              ├── task(recon, "enumerate 10.10.10.10")
              ├── task(recon, "web discovery on http://10.10.10.10")   # parallel fan-out
              ├── task(web-exploit, "test the login form for SQLi")     # after recon
              └── task(reporter, "write the report")                    # at the end
```

This already expresses **sequential** (recon → exploit → report) and
**parallel** (multiple recon tasks) patterns. Richer CAI patterns (swarm with
peer-to-peer handoff, conditional routing) arrive in Phase 2 via the plugin —
see [architecture.md](./architecture.md).

## Per-agent tool categories (example)

`recon` is restricted from exploitation by denying those binaries in its
frontmatter, while leaving recon/readonly commands to the global HITL gate:

```yaml
permission:
  bash:
    "*": ask          # everything still goes through the HITL policy
    "sqlmap*": deny    # …but exploitation tools are off-limits for recon
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
