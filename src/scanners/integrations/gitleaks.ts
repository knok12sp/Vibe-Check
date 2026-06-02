import type { Scanner, ScanContext } from "../../core/types.js";
import { isCommandAvailable } from "../../utils/exec.js";

export const gitleaksScanner: Scanner = {
  id: "gitleaks",
  name: "Gitleaks Scanner",
  profile: "deep",
  requires: "repo",
  async scan(ctx: ScanContext): Promise<never[]> {
    if (!ctx.config.integrations.gitleaks) return [];

    const available = await isCommandAvailable("gitleaks");
    if (!available) {
      ctx.logger.warn("gitleaks CLI not found. Install with: brew install gitleaks");
      return [];
    }

    ctx.logger.debug("Gitleaks integration - full implementation in v2");
    return [];
  },
};
