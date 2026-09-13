import { z } from "zod";
import { defineTool, runTool } from "../../mcp/define-tool.js";
import { ipAbuse, ipInfo, ipRpki } from "../../network/ripe.js";

const resource = z.string().min(1).describe("IP address, prefix, or hostname RIPEstat accepts.");

export const tools = [
  defineTool(
    "ip_info",
    "IP info",
    "ASN, announced prefix, holder, and coarse geolocation from RIPEstat. No API key.",
    z.object({ resource }),
    (ctx, input) => runTool(ctx, () => ipInfo(input.resource))
  ),
  defineTool(
    "ip_abuse",
    "IP abuse contact",
    "Abuse contacts from RIPEstat for an IP or prefix. No API key.",
    z.object({ resource }),
    (ctx, input) => runTool(ctx, () => ipAbuse(input.resource))
  ),
  defineTool(
    "ip_rpki",
    "RPKI",
    "RPKI validity for the covering prefix and origin ASN from RIPEstat. No API key.",
    z.object({ resource }),
    (ctx, input) => runTool(ctx, () => ipRpki(input.resource))
  )
];
