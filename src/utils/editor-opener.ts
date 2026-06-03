import { spawn } from "node:child_process";

export type EditorName = "code" | "cursor" | string | null;

export function detectEditor(): EditorName {
  if (process.env.VSCODE_CWD) return "code";
  if (process.env.TERM_PROGRAM === "Cursor") return "cursor";
  if (process.env.EDITOR) return process.env.EDITOR;
  return null;
}

function buildArgs(editor: string, filePath: string, line: number): [string, string[]] {
  switch (editor) {
    case "code":
      return ["code", ["--goto", `${filePath}:${line}`]];
    case "cursor":
      return ["cursor", ["--goto", `${filePath}:${line}`]];
    default:
      return [editor, [`${filePath}:${line}`]];
  }
}

export function openInEditor(filePath: string, line: number): string {
  const editor = detectEditor();

  if (!editor) {
    return `No editor detected. Open manually: ${filePath}:${line}`;
  }

  const [command, args] = buildArgs(editor, filePath, line);

  const child = spawn(command, args, { detached: true, stdio: "ignore" });
  child.unref();

  return `Opened ${filePath}:${line} in ${editor}`;
}
