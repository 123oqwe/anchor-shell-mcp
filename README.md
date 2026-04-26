# anchor-shell-mcp

Safe shell-exec as an **MCP server**. The token-efficient alternative to wrapping every CLI in its own MCP. Mac / Win / Linux.

Built for [anchor](https://github.com/123oqwe/anchor-backend) but works with any MCP host (Claude Desktop, Cursor, etc).

## Why

Wrapping each CLI as its own structured MCP tool sounds clean, but it costs tokens on every turn — every tool's description + schema is shipped to the LLM. For ops with good CLIs (git, ls, find, ps, curl, awk, sed, sqlite3), that overhead is wasted.

This server exposes ONE primary tool (`shell_run`) that lets the agent compose any CLI it knows. Token cost example:

| same op | structured MCP | shell_run |
|--------|---------------|-----------|
| "list installed apps" | ~3000 tokens (JSON array of 100 entries) | ~400 tokens (`ls /Applications` plain text) |
| "git log last 10" | ~200 tokens schema + ~1000 tokens JSON | ~120 tokens output |

Save ~7-8x tokens for CLI-friendly ops.

## Tools (4)

| Tool | Description |
|------|------|
| `shell_run` | Execute a command (timeout + output cap + deny-list) |
| `shell_help` | Common recipe ideas (git / fs / ps / network / text) |
| `shell_status` | Platform / shell binary / restrictions config |
| `shell_history` | Last 30 commands run via shell_run |

## Install

```bash
npx -y @anchor/shell-mcp
```

## Use with anchor-backend

```bash
curl -X POST http://localhost:3001/api/mcp/servers -H "Content-Type: application/json" -d '{
  "name": "anchor-shell",
  "command": "npx",
  "args": ["-y", "@anchor/shell-mcp"]
}'
```

After connect, 4 tools register as `mcp_anchor_shell_*`. Agents prefer `shell_run` for git/fs/ps/curl ops — saves tokens vs the structured equivalents.

## Use with Claude Desktop

```json
{
  "mcpServers": {
    "anchor-shell": {
      "command": "npx",
      "args": ["-y", "@anchor/shell-mcp"]
    }
  }
}
```

## Safety

Built-in deny-list blocks:
- `sudo`
- `rm -rf /`, `rm -rf $HOME`, `rm -rf ~`
- Classic fork bomb `:(){ :|:& };:`
- `mkfs`, `dd if=... of=/dev/...`
- `shutdown` / `reboot` / `halt` / `poweroff`
- `curl | sh` / `wget | sh` (pipe-to-shell from network)
- `nc -e` reverse shell

Per-call safeguards:
- Default timeout 30s (max 120s)
- Output capped at 16KB (max 64KB)
- Optional cwd-restriction via `ANCHOR_SHELL_ALLOWED_DIRS=path1:path2` env var
- Optional PATH override via `ANCHOR_SHELL_PATH` env var

## What this does NOT prevent

- Running arbitrary CLIs the user has installed (intentional — that's the value)
- Network calls via `curl` etc. (caller responsibility)
- Filesystem writes within allowed dirs

If you need stricter sandboxing, run anchor-shell-mcp inside a container or with a chrooted user.

## Companion to other anchor MCPs

| Use shell_run for | Use a dedicated MCP for |
|-------------------|-----------------------|
| git / ls / find / cat / grep / ps / curl / awk / sed / sqlite3 | mail / calendar / notes (apple-mcp) |
| One-off file inspections | Activity tracking (anchor-activity-mcp) |
| Quick system queries | Browser history (anchor-browser-mcp) |
| Custom pipelines | Desktop GUI control (anchor-input-mcp) |
| | Screen content via VLM (anchor-screen-mcp) |
| | Installed apps with version info (anchor-system-mcp) |

## License

MIT
