import { z } from "zod";
import { defineTool, runTool } from "../../mcp/define-tool.js";
import { DEFAULT_NAMESERVERS, parseNameservers } from "../../network/resolvers.js";

export const tools = [
  defineTool(
    "network_whoami",
    "Who am I",
    "Show session nameservers. Secrets are never returned.",
    z.object({}),
    (ctx) =>
      runTool(ctx, async () => ({
        accountLabel: ctx.bag.claims.accountLabel ?? null,
        nameservers: parseNameservers(ctx.bag.claims.nameservers),
        defaultNameservers: [...DEFAULT_NAMESERVERS]
      }))
  )
];
