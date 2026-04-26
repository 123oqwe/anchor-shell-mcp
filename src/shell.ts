/**
 * Safe shell exec. The agent provides a command string; we run it with
 * deny-list + timeout + output cap, and return stdout/stderr/exitCode.
 *
 * Why not wrap each CLI in its own MCP tool? Token cost.
 * Each MCP tool ships its description + schema every turn. For ops with
 * good CLIs (git, ls, find, ps, curl), shell exec wins big on tokens.
 *
 * Safety:
 *   1. Deny-list patterns block obviously destructive commands.
 *   2. Timeout (default 30s, max 120s) prevents fork bombs / runaway loops.
 *   3. Output capped at 16KB (configurable, max 64KB).
 *   4. Optional cwd-restriction via env ANCHOR_SHELL_ALLOWED_DIRS (colon-list
 *      of dirs the cwd must be inside; empty = no restriction).
 *   5. PATH-restricted shells via env ANCHOR_SHELL_PATH override.
 *
 * What this does NOT protect against:
 *   - Running arbitrary CLIs the user has installed (intentional — that's
 *     what makes it useful).
 *   - Network calls (use at your own risk; agent gating in anchor-backend
 *     marks shell as send_external by default).
 */
import { spawn } from "node:child_process";
import os from "node:os";

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 120_000;
const DEFAULT_OUTPUT_CAP = 16 * 1024;
const MAX_OUTPUT_CAP = 64 * 1024;

const DENY_PATTERNS: RegExp[] = [
  /\bsudo\b/,                      // privilege escalation
  /\brm\s+-rf\s+(\/|\$HOME|~)/,    // catastrophic deletes
  /:\(\)\s*\{\s*:\|:&\s*\};:/,     // classic fork bomb
  /\b(mkfs|dd\s+if=.*\bof=\/dev)/, // disk-wipe
  /\b(shutdown|reboot|halt|poweroff)\b/,
  /\bcurl\s+.*\|\s*(sh|bash|zsh)/, // pipe-to-shell from network
  /\bwget\s+.*\|\s*(sh|bash|zsh)/,
  /\b(nc|netcat)\s+.*\s+-e\b/,     // reverse shell
];

export interface ShellResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
  elapsedMs: number;
  truncated: boolean;
  cmd: string;
}

const HISTORY_MAX = 50;
const history: { cmd: string; ts: string; exitCode: number | null; ok: boolean }[] = [];

function isDenied(cmd: string): { denied: boolean; reason?: string } {
  for (const re of DENY_PATTERNS) {
    if (re.test(cmd)) return { denied: true, reason: `matches deny pattern ${re}` };
  }
  return { denied: false };
}

export async function runShell(input: { command: string; timeoutMs?: number; outputCap?: number; cwd?: string }): Promise<ShellResult> {
  const start = Date.now();
  const cmd = (input.command ?? "").trim();
  if (!cmd) return { ok: false, stdout: "", stderr: "empty command", exitCode: null, signal: null, elapsedMs: 0, truncated: false, cmd };

  const deny = isDenied(cmd);
  if (deny.denied) {
    return { ok: false, stdout: "", stderr: `[anchor-shell] BLOCKED: ${deny.reason}`, exitCode: null, signal: null, elapsedMs: 0, truncated: false, cmd };
  }

  const timeoutMs = Math.min(input.timeoutMs ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const outputCap = Math.min(input.outputCap ?? DEFAULT_OUTPUT_CAP, MAX_OUTPUT_CAP);

  // cwd restriction (empty env var = no restriction)
  const allowed = (process.env.ANCHOR_SHELL_ALLOWED_DIRS ?? "").split(":").filter(Boolean);
  const cwd = input.cwd ?? os.homedir();
  if (allowed.length > 0 && !allowed.some(d => cwd.startsWith(d))) {
    return { ok: false, stdout: "", stderr: `[anchor-shell] cwd '${cwd}' outside ANCHOR_SHELL_ALLOWED_DIRS`, exitCode: null, signal: null, elapsedMs: 0, truncated: false, cmd };
  }

  return await new Promise<ShellResult>((resolve) => {
    const sh = process.platform === "win32" ? "cmd" : "/bin/bash";
    const args = process.platform === "win32" ? ["/c", cmd] : ["-c", cmd];
    const env: Record<string, string> = { ...process.env as any };
    if (process.env.ANCHOR_SHELL_PATH) env.PATH = process.env.ANCHOR_SHELL_PATH;
    const proc = spawn(sh, args, { cwd, env, timeout: timeoutMs });

    let stdout = "", stderr = "";
    let truncated = false;
    proc.stdout.on("data", (d: Buffer) => {
      const chunk = d.toString();
      if (stdout.length + chunk.length > outputCap) {
        stdout += chunk.slice(0, outputCap - stdout.length);
        truncated = true;
      } else stdout += chunk;
    });
    proc.stderr.on("data", (d: Buffer) => {
      const chunk = d.toString();
      if (stderr.length + chunk.length > outputCap) {
        stderr += chunk.slice(0, outputCap - stderr.length);
        truncated = true;
      } else stderr += chunk;
    });
    proc.on("close", (code, signal) => {
      const result: ShellResult = {
        ok: code === 0,
        stdout, stderr,
        exitCode: code, signal: signal as string | null,
        elapsedMs: Date.now() - start,
        truncated, cmd,
      };
      history.unshift({ cmd, ts: new Date().toISOString(), exitCode: code, ok: code === 0 });
      while (history.length > HISTORY_MAX) history.pop();
      resolve(result);
    });
    proc.on("error", (err: any) => {
      resolve({ ok: false, stdout: "", stderr: err?.message ?? String(err), exitCode: null, signal: null, elapsedMs: Date.now() - start, truncated: false, cmd });
    });
  });
}

export function shellHistory(): typeof history {
  return history.slice(0, 30);
}

export function shellStatus() {
  const allowed = (process.env.ANCHOR_SHELL_ALLOWED_DIRS ?? "").split(":").filter(Boolean);
  return {
    platform: process.platform,
    shell: process.platform === "win32" ? "cmd" : "/bin/bash",
    cwdRestricted: allowed.length > 0,
    allowedDirs: allowed,
    pathOverride: process.env.ANCHOR_SHELL_PATH ? "set" : "default",
    denyPatternCount: DENY_PATTERNS.length,
    defaultTimeoutMs: DEFAULT_TIMEOUT_MS,
    maxTimeoutMs: MAX_TIMEOUT_MS,
    defaultOutputCap: DEFAULT_OUTPUT_CAP,
    maxOutputCap: MAX_OUTPUT_CAP,
    historySize: history.length,
  };
}

const COMMON_RECIPES = `Common recipes (ideas — not an allowlist):

git:
  git -C <repo> log -10 --oneline
  git -C <repo> status --short
  git -C <repo> diff --stat HEAD~1

filesystem:
  ls /Applications | head -50
  find ~/code -name "*.ts" -mtime -7 | head -20
  cat ~/.zshrc | grep -i alias
  du -sh ~/Downloads/*

processes:
  ps -A -o pid,pcpu,pmem,comm | sort -k2 -nr | head -10
  lsof -p <pid>

network:
  curl -s https://api.example.com/foo | jq .
  ping -c 3 example.com

text:
  grep -rn "TODO" ~/code --include="*.ts"
  awk '{print $1}' file.csv | sort | uniq -c

system:
  sw_vers                 # macOS
  uname -a                # *nix
  df -h                   # disk
  uptime`;

export function shellHelp(): string {
  return COMMON_RECIPES;
}
