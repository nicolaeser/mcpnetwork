import {
  lookupSafe,
  mxExchanges,
  nodeLookup,
  readSoaSerial,
  stringRecords,
  type LookupFn,
  type LookupResult
} from "./dns.js";
import { parseNameservers } from "./resolvers.js";

export interface AddressSet {
  readonly A: LookupResult;
  readonly AAAA: LookupResult;
}

export interface DnsZoneReport {
  readonly domain: string;
  readonly nameservers: string[];
  readonly ok: boolean;
  readonly issues: string[];
  readonly soa: LookupResult;
  readonly serialsAgree: boolean;
  readonly soaByNs: Record<string, LookupResult>;
  readonly ns: string[];
  readonly nsAddresses: Record<string, AddressSet>;
  readonly mx: LookupResult;
  readonly mxAddresses: Record<string, AddressSet>;
  readonly A: LookupResult;
  readonly AAAA: LookupResult;
}

export async function dnsCheckZone(input: {
  readonly domain: string;
  readonly nameservers?: string | readonly string[];
  readonly lookup?: LookupFn;
}): Promise<DnsZoneReport> {
  const domain = input.domain.replace(/\.$/, "").toLowerCase();
  const servers = parseNameservers(input.nameservers);
  const lookup = input.lookup ?? nodeLookup;
  const issues: string[] = [];
  const soa = await lookupSafe(lookup, domain, "SOA", servers);
  if (!soa.ok) issues.push(`No SOA: ${soa.message}`);
  const ns = await lookupSafe(lookup, domain, "NS", servers);
  const nsHosts = ns.ok ? stringRecords(ns.records) : [];
  if (!ns.ok || nsHosts.length === 0) issues.push("No NS records.");
  const nsAddresses: Record<string, AddressSet> = {};
  const soaByNs: Record<string, LookupResult> = {};
  const serials: number[] = [];
  for (const host of nsHosts) {
    const a = await lookupSafe(lookup, host, "A", servers);
    const aaaa = await lookupSafe(lookup, host, "AAAA", servers);
    nsAddresses[host] = { A: a, AAAA: aaaa };
    if (!a.ok && !aaaa.ok) issues.push(`NS ${host} has no A/AAAA.`);
    const ips = [...ipsOf(a), ...ipsOf(aaaa)];
    const soaAt = await lookupSafe(lookup, domain, "SOA", ips.length > 0 ? ips : servers);
    soaByNs[host] = soaAt;
    const serial = soaAt.ok ? readSoaSerial(soaAt.records) : undefined;
    if (serial !== undefined) serials.push(serial);
  }
  const serialsAgree = serials.length > 0 && serials.every((item) => item === serials[0]);
  if (serials.length > 1 && !serialsAgree) issues.push("SOA serials differ across NS.");
  const cname = await lookupSafe(lookup, domain, "CNAME", servers);
  if (cname.ok) issues.push("CNAME at zone apex.");
  const mx = await lookupSafe(lookup, domain, "MX", servers);
  const mxHosts = mx.ok ? mxExchanges(mx.records) : [];
  const mxAddresses: Record<string, AddressSet> = {};
  for (const host of mxHosts) {
    const a = await lookupSafe(lookup, host, "A", servers);
    const aaaa = await lookupSafe(lookup, host, "AAAA", servers);
    mxAddresses[host] = { A: a, AAAA: aaaa };
    if (!a.ok && !aaaa.ok) issues.push(`MX ${host} has no A/AAAA.`);
  }
  const a = await lookupSafe(lookup, domain, "A", servers);
  const aaaa = await lookupSafe(lookup, domain, "AAAA", servers);
  return {
    domain,
    nameservers: servers,
    ok: issues.length === 0,
    issues,
    soa,
    serialsAgree,
    soaByNs,
    ns: nsHosts,
    nsAddresses,
    mx,
    mxAddresses,
    A: a,
    AAAA: aaaa
  };
}

function ipsOf(result: LookupResult): string[] {
  if (!result.ok) return [];
  return stringRecords(result.records);
}
