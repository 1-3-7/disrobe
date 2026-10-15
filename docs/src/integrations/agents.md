# Agent setup

`disrobe agent setup` registers the [MCP server](./mcp.md) with coding agents by editing each agent's user-level configuration file, and installs an investigation skill where the agent reads skills from a directory. Every change is shown as a unified diff first; nothing is written without consent.

```sh
disrobe agent setup                               # every agent whose configuration directory exists
disrobe agent setup --agent codex --agent cursor  # only these agents
disrobe agent setup --root /srv/samples           # let the server read /srv/samples as well
disrobe agent status                              # what each agent has registered
disrobe agent remove                              # take the registration out again
```

## Supported agents

| `--agent` | Agent | Configuration file | Entry | Skill file |
|---|---|---|---|---|
| `claude-code` | Claude Code | `~/.claude.json`, or `$CLAUDE_CONFIG_DIR/.claude.json` | `mcpServers.disrobe`, `"type": "stdio"` | `~/.claude/skills/disrobe/SKILL.md`, or under `$CLAUDE_CONFIG_DIR/skills` |
| `claude-desktop` | Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json`; Linux `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json` | `mcpServers.disrobe` | none |
| `codex` | Codex | `~/.codex/config.toml`, or `$CODEX_HOME/config.toml` | `[mcp_servers.disrobe]` with `tool_timeout_sec = 1800` | `~/.agents/skills/disrobe/SKILL.md` |
| `cursor` | Cursor | `~/.cursor/mcp.json` | `mcpServers.disrobe`, `"type": "stdio"` | none |
| `gemini` | Gemini CLI | `~/.gemini/settings.json`, or `$GEMINI_CLI_HOME/.gemini/settings.json` | `mcpServers.disrobe` | `~/.agents/skills/disrobe/SKILL.md`, or under `$GEMINI_CLI_HOME` |
| `vscode` | VS Code | the user-profile `mcp.json`: Windows `%APPDATA%\Code\User\mcp.json`, macOS `~/Library/Application Support/Code/User/mcp.json`, Linux `$XDG_CONFIG_HOME/Code/User/mcp.json` | `servers.disrobe`, `"type": "stdio"` | none |
| `windsurf` | Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers.disrobe` | `~/.codeium/windsurf/skills/disrobe/SKILL.md` |
| `devin` | Devin Desktop | Windows `%APPDATA%\devin\mcp_config.json`; elsewhere `$XDG_CONFIG_HOME/devin/mcp_config.json` | `mcpServers.disrobe` | `~/.codeium/windsurf/skills/disrobe/SKILL.md` |
| `copilot` | GitHub Copilot CLI | `~/.copilot/mcp-config.json`, or `$COPILOT_HOME/mcp-config.json` | `mcpServers.disrobe`, `"type": "local"`, `"tools": ["*"]` | `~/.copilot/skills/disrobe/SKILL.md` |
| `qwen` | Qwen Code | `~/.qwen/settings.json`, or `$QWEN_HOME/settings.json` | `mcpServers.disrobe` | `~/.qwen/skills/disrobe/SKILL.md` |
| `opencode` | OpenCode | `~/.config/opencode/opencode.json` (`opencode.jsonc` when only that file exists), under `$XDG_CONFIG_HOME` when set | `mcp.disrobe`, `"type": "local"`, the command as an array, `"enabled": true` | `~/.config/opencode/skills/disrobe/SKILL.md` |
| `kimi` | Kimi Code | `~/.kimi-code/mcp.json`, or `$KIMI_CODE_HOME/mcp.json` | `mcpServers.disrobe` | `~/.agents/skills/disrobe/SKILL.md` |

`$XDG_CONFIG_HOME` defaults to `~/.config` and `%APPDATA%` to `~\AppData\Roaming`. An override that starts with `~` is expanded against the home directory; a relative one is resolved against the working directory.

On Windows, the Microsoft Store build of Claude Desktop keeps its own copy of the file at `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` once it has saved its settings, and reads that copy instead of the `%APPDATA%` file. Setup edits that copy when it exists. Quit Claude Desktop completely before running setup, because a running instance can write its configuration back from memory.

Devin Desktop is the current name of the Windsurf editor. Builds that still read `~/.codeium/windsurf/mcp_config.json` are configured with `--agent windsurf`; builds that read the Devin location are configured with `--agent devin`.

Without `--agent`, setup configures every agent whose configuration file or configuration directory exists. `--agent all` does the same and can be combined with named agents, which are configured even when their directory does not exist yet.

## What setup writes

The entry starts the running `disrobe` executable by its absolute path with the `mcp` subcommand, plus `--root <dir>` for each `--root` given to setup. For most agents it looks like this:

```json
{
  "mcpServers": {
    "disrobe": {
      "type": "stdio",
      "command": "/opt/disrobe/bin/disrobe",
      "args": ["mcp", "--root", "/srv/samples"]
    }
  }
}
```

Codex gets a TOML table. Its tool timeout is raised to 30 minutes so a long `run_command` (unpacking or decompiling a large file) is not cut off at the 60-second default:

```toml
[mcp_servers.disrobe]
command = "/opt/disrobe/bin/disrobe"
args = ["mcp"]
tool_timeout_sec = 1800
```

The server reads files inside the agent's working directory and the `--root` directories, and nowhere else; see the [MCP security posture](./mcp.md#security-posture).

## Review, backups and consent

Setup reads every selected file first and prints, per file, whether it will be created, updated or left unchanged, followed by a unified diff. Then:

- On a terminal, it asks `apply these changes? [y/N]`.
- `--yes` (`-y`) applies without asking.
- Without a terminal and without `--yes`, it prints the plan and writes nothing.
- `--dry-run` prints the plan and writes nothing.
- `--json` prints the plan, the diffs and the outcome as one JSON document (`disrobe.agent-plan/v1`) and never prompts.

Edits change only the `disrobe` entry. Other servers, other settings, key order, indentation and comments stay byte-for-byte as they were; JSON files with `//` and `/* */` comments and trailing commas (VS Code, Gemini CLI and OpenCode accept them) are edited in place. Before replacing an existing file, setup writes a copy beside it named `<file>.disrobe-backup-<UTC timestamp>`, then writes the new content to a temporary file in the same directory and renames it over the original. A run that would produce identical content writes nothing and makes no backup, so running setup twice is harmless.

Setup refuses, by file name and without writing anything, a configuration file that is not valid JSON or TOML, is not UTF-8, or holds the server table under a value that is not an object (`DR-CLI-0964`), and one it cannot read or that is larger than 64 MiB (`DR-CLI-0963`). If a file changes on disk while the prompt is open, setup stops before touching it (`DR-CLI-0968`).

## The investigation skill

Agents with a skill directory get `disrobe/SKILL.md` in it. The skill describes the workflow the tools are built for:

1. `open_target` on the file, keeping the `target_id`, SHA-256, format and architecture.
2. `target_layout` and `list_functions` for sections, imports, exports and functions.
3. `disassemble_function` and `decompile_function` on the functions that matter.
4. `references_to`, `call_path`, `neighborhood` and `xrefs` to follow callers, callees and data references.
5. `find_strings`, `read_bytes`, `search_bytes` and `locate` for data.
6. `run_command` for every other `disrobe` subcommand: `identify`, `auto`, `native unpack`, `py deob`, `strings`, `ioc` and the rest of the read-only set `list_commands` shows.
7. `add_note` and `list_notes` to keep findings with the target.

It asks the agent to report evidence (addresses, file offsets, section names, SHA-256 of inputs and recovered files) and to quote a refusal's `DR-*` code and reason as a finding.

Cursor, VS Code and Claude Desktop have no user skill directory. Setup leaves their instruction settings alone and prints where to paste the skill text instead: Cursor's Settings > Rules > User Rules, a user-level instructions file for VS Code chat, or a Claude Desktop project's instructions. When none of the selected agents has a skill directory, setup prints the text itself. Codex, Gemini CLI and Kimi Code share `~/.agents/skills`, so one file serves all three.

## Status

`disrobe agent status` reports, for every supported agent (or the ones named with `--agent`):

- whether the configuration file exists,
- whether it holds a `disrobe` entry,
- the command that entry runs, whether that file exists, and whether it is this `disrobe` binary,
- whether the skill file is installed.

A registration that points at another `disrobe` binary, or at a path that no longer exists after a move or an upgrade, shows up here; run setup again to point it at the current binary. `--json` prints the same as `disrobe.agent-status/v1`.

## Removal

`disrobe agent remove` deletes the `disrobe` entry from every agent that has one, or from the agents named with `--agent`, with the same diff, backup and consent rules as setup. Nothing else in the file changes: removing an entry that setup added to an existing server table restores the file byte-for-byte. In a JSON file, a server object that setup created stays behind empty. The skill file is deleted once no remaining registered agent uses its directory, and only when it is the disrobe skill: an unmodified copy goes without a backup, together with its then-empty `disrobe` directory, and an edited copy is backed up first.

## Limits

- Only user-level files are edited. Project files such as `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json` or a project `.codex/config.toml` are left alone, and an agent may let a same-named project entry replace the user entry.
- Agents read their configuration at start; restart them after setup or removal.
- The registration records this binary's absolute path. Re-run setup after moving or reinstalling `disrobe` elsewhere.
- Setup needs a `disrobe` build with the default `server` feature, because the entry runs `disrobe mcp`.
