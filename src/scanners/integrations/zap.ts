import type { Scanner, ScanContext } from "../../core/types.js";
import { isCommandAvailable } from "../../utils/exec.js";

export const zapScanner: Scanner = {
  id: "zap",
  name: "ZAP Scanner",
  profile: "deep",
  requires: "url",
  async scan(ctx: ScanContext): Promise<never[]> {
    if (!ctx.config.integrations.zap) return [];

    const available = await isCommandAvailable("zap-cli");
    if (!available) {
      ctx.logger.warn("zap-cli not found. Install with: pip install zap-cli");
      return [];
    }

    ctx.logger.debug("ZAP integration - full implementation in v2");
    return [];
  },
};
