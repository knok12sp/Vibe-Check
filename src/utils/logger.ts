import chalk from "chalk";
import type { Logger } from "../core/types.js";

export function createLogger(verbose = false): Logger {
  return {
    info(msg: string) {
      console.log(chalk.blue("i"), msg);
    },
    warn(msg: string) {
      console.log(chalk.yellow("!"), msg);
    },
    error(msg: string) {
      console.error(chalk.red("x"), msg);
    },
    debug(msg: string) {
      if (verbose) console.log(chalk.gray("-"), msg);
    },
    success(msg: string) {
      console.log(chalk.green("+"), msg);
    },
  };
}
