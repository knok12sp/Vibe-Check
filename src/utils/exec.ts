import { spawn } from "node:child_process";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

export function execCommand(
  command: string,
  args: string[],
  options: { cwd?: string; timeout?: number },
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      timeout: options.timeout ?? 60_000,
      shell: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    child.stderr?.on("data", (data: Buffer) => {
      stderr += data.toString();
    });
    child.on("error", (err: Error & { code?: string }) => {
      if (err.code === "ENOENT")
        resolve({ stdout: "", stderr: `${command}: not found`, exitCode: 127 });
      else reject(err);
    });
    child.on("close", (code) => {
      resolve({ stdout, stderr, exitCode: code });
    });
  });
}

export async function isCommandAvailable(command: string): Promise<boolean> {
  try {
    const r = await execCommand(command, ["--version"], { timeout: 10_000 });
    return r.exitCode === 0;
  } catch {
    return false;
  }
}
