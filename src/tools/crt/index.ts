import { z } from "zod";
import { defineTool, runTool } from "../../mcp/define-tool.js";
import { crtIssuances, crtNameSearch } from "../../network/crt.js";

export const tools = [
  defineTool(
    "crt_subdomains",
    "CT subdomains",
    "Subdomains indexed by crt.name for an apex (eTLD+1). Free, no token, 100 requests per IP per day. Does not include certificate metadata.",
    z.object({
      apex: z.string().min(1).describe("eTLD+1 such as example.com"),
      contains: z.string().optional().describe("Keep names containing this substring."),
      since: z.string().optional().describe("ISO-8601 lower bound on first_seen, e.g. 2024-01-01T00:00:00Z"),
      limit: z.number().int().min(1).max(2_000).optional()
    }),
    (_ctx, input) =>
      runTool(_ctx, () =>
        crtNameSearch({
          apex: input.apex,
          ...(input.contains === undefined ? {} : { contains: input.contains }),
          ...(input.since === undefined ? {} : { since: input.since }),
          ...(input.limit === undefined ? {} : { limit: input.limit })
        })
      )
  ),
  defineTool(
    "crt_certs",
    "CT certificates",
    "Certificate Transparency issuances from Cert Spotter: SAN names, issuer, validity, revocation, fingerprints. No API key.",
    z.object({
      domain: z.string().min(1),
      includeSubdomains: z.boolean().optional(),
      matchWildcards: z.boolean().optional(),
      after: z.string().optional().describe("Cert Spotter issuance id to page after."),
      limit: z.number().int().min(1).max(100).optional()
    }),
    (_ctx, input) =>
      runTool(_ctx, () =>
        crtIssuances({
          domain: input.domain,
          ...(input.includeSubdomains === undefined ? {} : { includeSubdomains: input.includeSubdomains }),
          ...(input.matchWildcards === undefined ? {} : { matchWildcards: input.matchWildcards }),
          ...(input.after === undefined ? {} : { after: input.after }),
          ...(input.limit === undefined ? {} : { limit: input.limit })
        })
      )
  )
];
