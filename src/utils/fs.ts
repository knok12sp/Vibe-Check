import { readFileSync, existsSync, statSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { extname, basename, resolve } from "node:path";

export async function fileExists(path: string): Promise<boolean> {
  try { await stat(path); return true; } catch { return false; }
}
export function fileExistsSync(path: string): boolean { return existsSync(path); }
export function isDirectory(path: string): boolean {
  try { return statSync(path).isDirectory(); } catch { return false; }
}
export async function readTextFile(path: string): Promise<string> { return readFile(path, "utf-8"); }
export function readTextFileSync(path: string): string { return readFileSync(path, "utf-8"); }
export function getExtension(path: string): string { return extname(path).toLowerCase(); }
export function getBaseName(path: string): string { return basename(path); }
export function resolvePath(...segments: string[]): string { return resolve(...segments); }
