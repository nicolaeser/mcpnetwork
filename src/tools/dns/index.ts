import { z } from "zod";
import { defineTool, runTool } from "../../mcp/define-tool.js";
import { dnsLookup, dnsReverse, RR_TYPES } from "../../network/dns.js";
import { dnsCompare } from "../../network/compare.js";
import { dnsTrace } from "../../network/trace.js";
import { dnsCheckZone } from "../../network/zone.js";
import { dnsMailAuth } from "../../network/mail.js";
import { dnsDnssec } from "../../network/dnssec.js";
import { nameserversFromBag } from "../../network/resolvers.js";
import {
  createCheckHostClient,
  startCheckHost,
  waitCheckHostResult
} from "../../network/checkhost.js";
import { timeoutMsField, waitField, waitTimeoutMsField } from "../fields.js";

const rrType = z.enum(RR_TYPES);

export const tools = [
  defineTool(
    "dns_lookup",
    "DNS lookup",
    "Resolve a name against chosen nameservers. Default is Cloudflare 1.1.1.1 and 1.0.0.1. HTTPS, SVCB, DS, and DNSKEY use DNS-over-HTTPS.",
    z.object({
      name: z.string().min(1),
      type: rrType.optional(),
      nameservers: z.string().optional().describe("Comma-separated IPs. Overrides the session default.")
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        dnsLookup({
          name: input.name,
          ...(input.type === undefined ? {} : { type: input.type }),
          nameservers: nameserversFromBag(ctx.bag.claims, input.nameservers)
        })
      )
  ),
  defineTool(
    "dns_reverse",
    "Reverse DNS",
    "PTR lookup for an IPv4 or IPv6 address.",
    z.object({
      ip: z.string().min(1),
      nameservers: z.string().optional()
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        dnsReverse({
          ip: input.ip,
          nameservers: nameserversFromBag(ctx.bag.claims, input.nameservers)
        })
      )
  ),
  defineTool(
    "dns_trace",
    "DNS trace",
    "Walk NS from the root to the name, then query the requested type at the leaf nameservers.",
    z.object({
      name: z.string().min(1),
      type: rrType.optional()
    }),
    (_ctx, input) =>
      runTool(_ctx, () =>
        dnsTrace({ name: input.name, ...(input.type === undefined ? {} : { type: input.type }) })
      )
  ),
  defineTool(
    "dns_compare",
    "DNS compare",
    "Query the same name/type on Cloudflare, Google, Quad9, and optional extra resolvers.",
    z.object({
      name: z.string().min(1),
      type: rrType.optional(),
      extra: z.string().optional().describe("Optional extra comma-separated resolver IPs, queried in addition to the public set.")
    }),
    (_ctx, input) =>
      runTool(_ctx, () =>
        dnsCompare({
          name: input.name,
          ...(input.type === undefined ? {} : { type: input.type }),
          ...(input.extra === undefined ? {} : { extra: input.extra })
        })
      )
  ),
  defineTool(
    "dns_check_zone",
    "DNS zone check",
    "SOA/NS glue, SOA serials across NS, MX addresses, and apex CNAME sanity for a domain.",
    z.object({
      domain: z.string().min(1),
      nameservers: z.string().optional()
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        dnsCheckZone({
          domain: input.domain,
          nameservers: nameserversFromBag(ctx.bag.claims, input.nameservers)
        })
      )
  ),
  defineTool(
    "dns_mail_auth",
    "Mail auth",
    "SPF, DMARC, BIMI, and common DKIM selectors from TXT records.",
    z.object({
      domain: z.string().min(1),
      nameservers: z.string().optional(),
      dkimSelectors: z.array(z.string().min(1)).max(8).optional()
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        dnsMailAuth({
          domain: input.domain,
          nameservers: nameserversFromBag(ctx.bag.claims, input.nameservers),
          ...(input.dkimSelectors === undefined ? {} : { dkimSelectors: input.dkimSelectors })
        })
      )
  ),
  defineTool(
    "dns_dnssec",
    "DNSSEC",
    "DS and DNSKEY plus the DoH authenticated-data flag for A/AAAA.",
    z.object({
      domain: z.string().min(1),
      nameservers: z.string().optional()
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        dnsDnssec({
          domain: input.domain,
          nameservers: nameserversFromBag(ctx.bag.claims, input.nameservers)
        })
      )
  ),
  defineTool(
    "dns_propagation",
    "DNS propagation",
    "Resolve a name from Check-Host nodes worldwide.",
    z.object({
      host: z.string().min(1),
      maxNodes: z.number().int().min(1).max(50).optional(),
      nodes: z.array(z.string()).optional(),
      wait: waitField,
      waitTimeoutMs: waitTimeoutMsField,
      timeoutMs: timeoutMsField
    }),
    (_ctx, input) =>
      runTool(_ctx, async () => {
        const client = createCheckHostClient();
        const started = await startCheckHost(client, "dns", input.host, {
          ...(input.maxNodes === undefined ? {} : { maxNodes: input.maxNodes }),
          ...(input.nodes === undefined ? {} : { nodes: input.nodes })
        });
        if (input.wait === false) return started;
        const results = await waitCheckHostResult(
          client,
          started.request_id,
          input.waitTimeoutMs ?? input.timeoutMs ?? 20_000
        );
        return { ...started, results };
      })
  )
];
