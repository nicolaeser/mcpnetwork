import { lookupSafe, nodeLookup, stringRecords, type LookupFn, type LookupResult, type RrType } from "./dns.js";

const ROOT_HINTS = ["198.41.0.4", "199.9.14.201", "192.33.4.12"] as const;

export interface DnsTraceHop {
  readonly zone: string;
  readonly nameservers: string[];
  readonly role?: "root-hints";
  readonly nsHosts?: string[];
  readonly ns?: LookupResult;
}

export interface DnsTraceReport {
  readonly name: string;
  readonly type: RrType;
  readonly hops: DnsTraceHop[];
  readonly answer: LookupResult;
}

export async function dnsTrace(input: {
  readonly name: string;
  readonly type?: RrType;
  readonly lookup?: LookupFn;
}): Promise<DnsTraceReport> {
  const type = input.type ?? "A";
  const lookup = input.lookup ?? nodeLookup;
  const fqdn = input.name.replace(/\.$/, "").toLowerCase();
  const labels = fqdn.split(".").filter((part) => part.length > 0);
  const zones: string[] = [];
  for (let i = labels.length - 1; i >= 0; i--) {
    zones.push(labels.slice(i).join("."));
  }
  const hops: DnsTraceHop[] = [{ zone: ".", nameservers: [...ROOT_HINTS], role: "root-hints" }];
  let servers: string[] = [...ROOT_HINTS];
  for (const zone of zones) {
    const ns = await lookupSafe(lookup, zone, "NS", servers);
    if (!ns.ok) {
      hops.push({ zone, nameservers: servers, ns });
      break;
    }
    const nsHosts = stringRecords(ns.records);
    const next: string[] = [];
    for (const host of nsHosts) {
      const a = await lookupSafe(lookup, host, "A", servers);
      if (a.ok) next.push(...stringRecords(a.records));
    }
    hops.push({ zone, nsHosts, nameservers: next.length > 0 ? next : servers });
    if (next.length > 0) servers = next;
  }
  return { name: fqdn, type, hops, answer: await lookupSafe(lookup, fqdn, type, servers) };
}
