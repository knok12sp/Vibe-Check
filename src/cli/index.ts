#!/usr/bin/env node
import { Command } from "commander";
import { createLogger } from "../utils/logger.js";
import { initCommand } from "./commands/init.js";
import { scanRepoCommand, scanUrlCommand, scanFullCommand } from "./commands/scan.js";
import { reportCommand } from "./commands/report.js";

const program = new Command();

program
  .name("vibe-guard")
  .version("0.1.0")
  .description("Local-first security scanner for AI-generated websites and web apps");

program
  .command("init")
  .description("Create a vibe-guard.config.json in the current directory")
  .action(() => {
    const logger = createLogger();
    initCommand(logger);
  });

const scanCommand = program
  .command("scan")
  .description("Run a security scan");

scanCommand
  .command("repo")
  .description("Scan a local repository")
  .argument("<path>", "Path to the repository")
  .option("-p, --profile <profile>", "Scan profile: quick, standard, deep", "standard")
  .option("--json [file]", "Output JSON report to file")
  .option("--md [file]", "Output Markdown report to file")
  .option("--html [file]", "Output HTML report to file")
  .option("--sarif [file]", "Output SARIF report to file")
  .option("--fail-on <severity>", "Exit with non-zero if findings at this severity or higher", "high")
  .action((path, opts) => {
    const logger = createLogger();
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
  .option("--fail-on <severity>", "Exit with non-zero if findings at this severity or higher", "high")
  .action((url, opts) => {
    const logger = createLogger();
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
  .option("--fail-on <severity>", "Exit with non-zero if findings at this severity or higher", "high")
  .action((path, url, opts) => {
    const logger = createLogger();
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
    const logger = createLogger();
    reportCommand(file, opts, logger);
  });

program.parse(process.argv);
