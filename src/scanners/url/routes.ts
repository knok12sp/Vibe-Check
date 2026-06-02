import type { Scanner, ScanContext } from "../../core/types.js";

export const routesScanner: Scanner = {
  id: "routes",
  name: "Route Discovery Scanner",
  profile: "deep",
  requires: "url",
  async scan(ctx: ScanContext): Promise<never[]> {
    ctx.logger.debug("Route Discovery Scanner: full implementation available in v2");
    return [];
  },
};
