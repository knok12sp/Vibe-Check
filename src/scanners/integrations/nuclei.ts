import type { Scanner, ScanContext } from "../../core/types.js";
import { isCommandAvailable } from "../../utils/exec.js";

export const nucleiScanner: Scanner = {
  id: "nuclei",
  name: "Nuclei Scanner",
  profile: "deep",
  requires: "url",
  async scan(ctx: ScanContext): Promise<never[]> {
    if (!ctx.config.integrations.nuclei) return [];

    const available = await isCommandAvailable("nuclei");
    if (!available) {
      ctx.logger.warn("nuclei CLI not found. Install with: brew install nuclei or visit https://github.com/projectdiscovery/nuclei");
      return [];
    }

    ctx.logger.debug("Nuclei integration - full implementation in v2");
    return [];
  },
};
