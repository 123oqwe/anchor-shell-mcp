#!/usr/bin/env node
/**
 * anchor-shell-mcp — safe shell exec as MCP server.
 *
 * Speaks MCP 2025-06-18 over stdio. The agent provides a command string;
 * server runs it with deny-list + timeout + output cap.
 *
 * Token economy: instead of wrapping every CLI in its own MCP tool (each
 * shipping description + schema every turn), expose ONE shell_run that
 * lets the agent compose any CLI it knows. Saves ~7-8x tokens vs structured
 * MCP tools for ops with good CLIs (git, ls, find, ps, curl).
 *
 * Tools (3):
 *   shell_run     — execute a command with timeout + output cap
 *   shell_help    — list common recipes (ideas, not an allowlist)
 *   shell_status  — platform / cwd-restriction / deny-pattern count / history size
 *   shell_history — last N commands run (for debugging)
 */
import { runShell, shellHistory, shellStatus, shellHelp } from "./shell.js";

const PROTOCOL_VERSION = "2025-06-18";
const SERVER_INFO = { name: "anchor-shell-mcp", version: "0.1.0" };

interface JsonRpcRequest { jsonrpc: "2.0"; id?: number | string; method: string; params?: any }
interface JsonRpcResponse { jsonrpc: "2.0"; id: number | string; result?: any; error?: { code: number; message: string } }

const TOOLS = [
  {
    name: "shell_run",
    description: "Run a shell command. Use for git / ls / find / cat / grep / ps / curl / awk / sed / sqlite3. Deny-list blocks sudo / rm -rf / fork bombs. Default timeout 30s (max 120s), output cap 16KB. SANDBOX MODE: 'read-only' (default) blocks mv/cp/rm/mkdir/touch/sed -i/redirects/package mutations; 'workspace-write' allows writes only inside ANCHOR_SHELL_ALLOWED_DIRS; 'full' = no extra restriction.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Shell command (bash on *nix, cmd on Win)" },
        timeoutMs: { type: "number", description: "Override timeout (max 120000)" },
        outputCap: { type: "number", description: "Override output byte cap (max 65536)" },
        cwd: { type: "string", description: "Working directory (default: home)" },
        mode: { type: "string", enum: ["read-only", "workspace-write", "full"], description: "Sandbox mode (default: read-only)" },
      },
      required: ["command"],
    },
  },
  {
    name: "shell_help",
    description: "Common recipe ideas for shell_run (git / fs / processes / network / text / system). Not an allowlist — just a guide for the agent.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "shell_status",
    description: "Platform + shell binary + cwd-restriction config + deny-pattern count + recent-history size.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "shell_history",
    description: "Last 30 commands run via shell_run, with timestamp + exit code. Useful when the agent wants to recall what it just tried.",
    inputSchema: { type: "object", properties: {} },
  },
];

async function callTool(name: string, args: Record<string, any>): Promise<string> {
  switch (name) {
    case "shell_run": {
      if (!args.command) throw new Error("command required");
      const r = await runShell({ command: String(args.command), timeoutMs: args.timeoutMs, outputCap: args.outputCap, cwd: args.cwd, mode: args.mode });
      return JSON.stringify(r, null, 2);
    }
    case "shell_help": return shellHelp();
    case "shell_status": return JSON.stringify(shellStatus(), null, 2);
    case "shell_history": return JSON.stringify(shellHistory(), null, 2);
    default: throw new Error(`Unknown tool: ${name}`);
  }
}

async function handleRequest(req: JsonRpcRequest): Promise<JsonRpcResponse | null> {
  const id = req.id ?? 0;
  if (req.method === "initialize") {
    return { jsonrpc: "2.0", id, result: { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO } };
  }
  if (req.method === "notifications/initialized") return null;
  if (req.method === "tools/list") return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
  if (req.method === "tools/call") {
    const { name, arguments: args } = req.params ?? {};
    try {
      const text = await callTool(name, args ?? {});
      return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } };
    } catch (err: any) {
      return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `Error: ${err?.message ?? String(err)}` }], isError: true } };
    }
  }
  return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${req.method}` } };
}

let buffer = "";
process.stdin.setEncoding("utf-8");
process.stdin.on("data", async chunk => {
  buffer += chunk;
  let nl: number;
  while ((nl = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    try {
      const req: JsonRpcRequest = JSON.parse(line);
      const res = await handleRequest(req);
      if (res) process.stdout.write(JSON.stringify(res) + "\n");
    } catch (err: any) {
      process.stderr.write(`[parse-error] ${err?.message ?? err}\n`);
    }
  }
});
process.stdin.on("end", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));

process.stderr.write(`[anchor-shell-mcp] ready on stdio (platform=${process.platform})\n`);
