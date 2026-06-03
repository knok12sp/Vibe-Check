#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { createLogger } from "../utils/logger.js";
import { baselineInitCommand, baselineUpdateCommand } from "./commands/baseline.js";
import { initCommand } from "./commands/init.js";
import { installHooksCommand, removeHooksCommand } from "./commands/install-hooks.js";
import { reportCommand } from "./commands/report.js";
import { scanFullCommand, scanRepoCommand, scanUrlCommand } from "./commands/scan.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(__dirname, "..", "..", "package.json"), "utf-8"));

const program = new Command();

const VERBOSE_DEFAULT = false;

program
  .name("vibe-check")
  .version(pkg.version)
  .description("Local-first security scanner for AI-generated websites and web apps")
  .option("-v, --verbose", "Enable verbose debug output");

program
  .command("init")
  .description("Create a vibe-check.config.json in the current directory")
  .option("-f, --force", "Overwrite existing config")
  .action((opts) => {
    const logger = createLogger(program.opts().verbose);
    initCommand(opts.force ?? false, logger);
  });

const scanCommand = program.command("scan").description("Run a security scan");

scanCommand
  .command("repo")
  .description("Scan a local repository")
  .argument("<path>", "Path to the repository")
  .option("-p, --profile <profile>", "Scan profile: quick, standard, deep", "standard")
  .option("--json [file]", "Output JSON report to file")
  .option("--md [file]", "Output Markdown report to file")
  .option("--html [file]", "Output HTML report to file")
  .option("--sarif [file]", "Output SARIF report to file")
  .option(
    "--fail-on <severity>",
    "Exit with non-zero if findings at this severity or higher",
    "high",
  )
  .option("--baseline [file]", "Suppress known findings from baseline file")
  .action((path, opts) => {
    const logger = createLogger(program.opts().verbose);
    scanRepoCommand(path, opts, logger);
  });

scanCommand
  .command("url")
  .description("Scan a live URL")
  .argument("<url>", "URL to scan")
  .option("-p, --profile <profile>", "Scan profile: quick, standard, deep", "standard")
  .option("--json [file]", "Output JSON report to file")
  .option("--md [file]", "Output Markdown report to file")
  .option("--html [file]", "Output HTML report to file")
  .option("--sarif [file]", "Output SARIF report to file")
  .option(
    "--fail-on <severity>",
    "Exit with non-zero if findings at this severity or higher",
    "high",
  )
  .option("--baseline [file]", "Suppress known findings from baseline file")
  .action((url, opts) => {
    const logger = createLogger(program.opts().verbose);
    scanUrlCommand(url, opts, logger);
  });

scanCommand
  .command("full")
  .description("Scan a local repository and its live URL")
  .argument("<path>", "Path to the repository")
  .argument("<url>", "URL of the deployed site")
  .option("-p, --profile <profile>", "Scan profile: quick, standard, deep", "standard")
  .option("--json [file]", "Output JSON report to file")
  .option("--md [file]", "Output Markdown report to file")
  .option("--html [file]", "Output HTML report to file")
  .option("--sarif [file]", "Output SARIF report to file")
  .option(
    "--fail-on <severity>",
    "Exit with non-zero if findings at this severity or higher",
    "high",
  )
  .option("--baseline [file]", "Suppress known findings from baseline file")
  .action((path, url, opts) => {
    const logger = createLogger(program.opts().verbose);
    scanFullCommand(path, url, opts, logger);
  });

program
  .command("report")
  .description("Generate a report from a previous scan results JSON file")
  .argument("<file>", "Path to scan results JSON file")
  .option("--json [file]", "Output JSON report to file")
  .option("--md [file]", "Output Markdown report to file")
  .option("--html [file]", "Output HTML report to file")
  .option("--sarif [file]", "Output SARIF report to file")
  .action((file, opts) => {
    const logger = createLogger(program.opts().verbose);
    reportCommand(file, opts, logger);
  });

const baselineCmd = program
  .command("baseline")
  .description("Manage baseline suppression of known findings");

baselineCmd
  .command("init")
  .description("Create a baseline from a scan results JSON file")
  .argument("<file>", "Path to scan results JSON file")
  .action((file) => {
    const logger = createLogger(program.opts().verbose);
    baselineInitCommand(file, logger);
  });

baselineCmd
  .command("update")
  .description("Update baseline from latest scan results")
  .argument("<file>", "Path to scan results JSON file")
  .action((file) => {
    const logger = createLogger(program.opts().verbose);
    baselineUpdateCommand(file, logger);
  });

program
  .command("install-hooks")
  .description("Install VibeCheck pre-commit hook")
  .option("-f, --force", "Overwrite existing hook")
  .option("-r, --remove", "Remove installed hook")
  .action((opts) => {
    const logger = createLogger(program.opts().verbose);
    if (opts.remove) {
      removeHooksCommand(logger);
    } else {
      installHooksCommand(opts.force ?? false, logger);
    }
  });

program.parse(process.argv);
