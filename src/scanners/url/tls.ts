import type { Finding, ScanContext, Scanner } from "../../core/types.js";

export const tlsScanner: Scanner = {
  id: "tls",
  name: "TLS Checker",
  profile: "deep",
  requires: "url",
  async scan(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.config.integrations.nuclei) {
      ctx.logger.debug("TLS Checker: nuclei integration required but not enabled");
      return [];
    }
    ctx.logger.debug(
      "TLS Checker: full TLS scanning will be available in v2 with nuclei integration",
    );
    return [];
  },
};
