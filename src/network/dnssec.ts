import type { AxiosInstance } from "axios";
import { lookupSafe, nodeLookup, type LookupFn, type LookupResult } from "./dns.js";
import { dohLookup } from "./doh.js";
import { parseNameservers } from "./resolvers.js";

export interface DnsDnssecReport {
  readonly domain: string;
  readonly nameservers: string[];
  readonly ok: boolean;
  readonly issues: string[];
  readonly authenticated: boolean | null;
  readonly authenticatingType: "A" | "AAAA";
  readonly ds: LookupResult;
  readonly dnskey: LookupResult;
}

export async function dnsDnssec(input: {
  readonly domain: string;
  readonly nameservers?: string | readonly string[];
  readonly lookup?: LookupFn;
  readonly axiosInstance?: AxiosInstance;
}): Promise<DnsDnssecReport> {
  const domain = input.domain.replace(/\.$/, "").toLowerCase();
  const servers = parseNameservers(input.nameservers);
  const lookup = input.lookup ?? nodeLookup;
  const ds = await lookupSafe(lookup, domain, "DS", servers);
  const dnskey = await lookupSafe(lookup, domain, "DNSKEY", servers);
  let authenticated: boolean | null = null;
  let authenticatingType: "A" | "AAAA" = "A";
  try {
    authenticated = (await dohLookup(domain, "A", servers, input.axiosInstance)).ad;
  } catch {
    try {
      authenticated = (await dohLookup(domain, "AAAA", servers, input.axiosInstance)).ad;
      authenticatingType = "AAAA";
    } catch {
      authenticated = null;
    }
  }
  const issues: string[] = [];
  if (!ds.ok) issues.push("No DS at the parent.");
  if (!dnskey.ok) issues.push("No DNSKEY at the apex.");
  if (authenticated === false) issues.push("DoH AD flag was not set.");
  return {
    domain,
    nameservers: servers,
    ok: ds.ok && dnskey.ok && authenticated !== false,
    issues,
    authenticated,
    authenticatingType,
    ds,
    dnskey
  };
}
