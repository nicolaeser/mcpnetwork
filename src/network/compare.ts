import { dnsLookup, type DnsLookupReport, type LookupFn, type RrType } from "./dns.js";
import { DEFAULT_NAMESERVERS, parseNameservers } from "./resolvers.js";

export const PUBLIC_RESOLVER_GROUPS: readonly (readonly string[])[] = [
  [...DEFAULT_NAMESERVERS],
  ["8.8.8.8", "8.8.4.4"],
  ["9.9.9.9"]
];

export interface DnsCompareReport {
  readonly name: string;
  readonly type: RrType;
  readonly agree: boolean;
  readonly results: DnsLookupReport[];
}

export async function dnsCompare(input: {
  readonly name: string;
  readonly type?: RrType;
  readonly extra?: string | readonly string[];
  readonly resolvers?: readonly (string | readonly string[])[];
  readonly lookup?: LookupFn;
}): Promise<DnsCompareReport> {
  const type = input.type ?? "A";
  const extra =
    input.extra === undefined || (typeof input.extra === "string" && input.extra.trim().length === 0)
      ? []
      : parseNameservers(input.extra).map((ip) => [ip]);
  const groups =
    input.resolvers !== undefined && input.resolvers.length > 0
      ? input.resolvers
      : [...PUBLIC_RESOLVER_GROUPS, ...extra];
  const results: DnsLookupReport[] = [];
  for (const group of groups) {
    const nameservers = Array.isArray(group) ? [...group] : [group];
    results.push(
      await dnsLookup({
        name: input.name,
        type,
        nameservers,
        ...(input.lookup === undefined ? {} : { lookup: input.lookup })
      })
    );
  }
  const payloads = results.map((row) => JSON.stringify(row.ok ? row.records : { code: row.code, message: row.message }));
  const agree = payloads.every((item) => item === payloads[0]);
  return { name: input.name, type, agree, results };
}
