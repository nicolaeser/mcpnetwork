import type { CaaRecord, MxRecord, NaptrRecord, SoaRecord, SrvRecord, TlsaRecord } from "node:dns";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { dohLookup, isDohType, type DohRecord } from "./doh.js";
import { parseNameservers } from "./resolvers.js";
import { asFiniteNumber, asRecord, asString, errnoCode, errnoMessage, isRecord } from "./shape.js";

export const RR_TYPES = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "NS",
  "TXT",
  "SOA",
  "SRV",
  "CAA",
  "PTR",
  "NAPTR",
  "TLSA",
  "HTTPS",
  "SVCB",
  "DS",
  "DNSKEY"
] as const;

export type RrType = (typeof RR_TYPES)[number];

export type DnsRecords =
  | string[]
  | string[][]
  | MxRecord[]
  | NaptrRecord[]
  | SoaRecord
  | SrvRecord[]
  | CaaRecord[]
  | TlsaRecord[]
  | DohRecord[];

export type LookupFn = (name: string, type: RrType, servers: string[]) => Promise<DnsRecords>;

export type LookupOk<T extends DnsRecords = DnsRecords> = {
  readonly ok: true;
  readonly records: T;
};

export type LookupErr = {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
};

export type LookupResult<T extends DnsRecords = DnsRecords> = LookupOk<T> | LookupErr;

export type DnsLookupReport =
  | {
      readonly name: string;
      readonly type: RrType;
      readonly nameservers: string[];
      readonly ok: true;
      readonly records: DnsRecords;
    }
  | {
      readonly name: string;
      readonly type: RrType;
      readonly nameservers: string[];
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export type DnsReverseReport =
  | { readonly ip: string; readonly nameservers: string[]; readonly ok: true; readonly records: string[] }
  | {
      readonly ip: string;
      readonly nameservers: string[];
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export function createResolver(servers: readonly string[]): Resolver {
  const resolver = new Resolver();
  resolver.setServers([...servers]);
  return resolver;
}

export const nodeLookup: LookupFn = async (name, type, servers) => {
  if (isDohType(type)) {
    const result = await dohLookup(name, type, servers);
    return result.records;
  }
  const resolver = createResolver(servers);
  switch (type) {
    case "A":
      return resolver.resolve4(name);
    case "AAAA":
      return resolver.resolve6(name);
    case "CNAME":
      return resolver.resolveCname(name);
    case "MX":
      return resolver.resolveMx(name);
    case "NS":
      return resolver.resolveNs(name);
    case "TXT":
      return resolver.resolveTxt(name);
    case "SOA":
      return resolver.resolveSoa(name);
    case "SRV":
      return resolver.resolveSrv(name);
    case "CAA":
      return resolver.resolveCaa(name);
    case "PTR":
      return resolver.resolvePtr(name);
    case "NAPTR":
      return resolver.resolveNaptr(name);
    case "TLSA":
      return resolver.resolveTlsa(name);
    default:
      throw new Error(`Unsupported record type: ${type}`);
  }
};

export async function lookupSafe(
  lookup: LookupFn,
  name: string,
  type: RrType,
  servers: string[]
): Promise<LookupResult> {
  try {
    return { ok: true, records: await lookup(name, type, servers) };
  } catch (error) {
    return { ok: false, code: errnoCode(error), message: errnoMessage(error) };
  }
}

export async function dnsLookup(input: {
  readonly name: string;
  readonly type?: RrType;
  readonly nameservers?: string | readonly string[];
  readonly lookup?: LookupFn;
}): Promise<DnsLookupReport> {
  const type = input.type ?? "A";
  const servers = parseNameservers(input.nameservers);
  const lookup = input.lookup ?? nodeLookup;
  const result = await lookupSafe(lookup, input.name, type, servers);
  return result.ok
    ? { name: input.name, type, nameservers: servers, ok: true, records: result.records }
    : { name: input.name, type, nameservers: servers, ok: false, code: result.code, message: result.message };
}

export type ReverseFn = (ip: string, servers: string[]) => Promise<string[]>;

export const nodeReverse: ReverseFn = async (ip, servers) => {
  if (isIP(ip) === 0) throw new Error(`Not an IP address: ${ip}`);
  return createResolver(servers).reverse(ip);
};

export async function dnsReverse(input: {
  readonly ip: string;
  readonly nameservers?: string | readonly string[];
  readonly reverse?: ReverseFn;
}): Promise<DnsReverseReport> {
  const servers = parseNameservers(input.nameservers);
  const reverse = input.reverse ?? nodeReverse;
  try {
    return { ip: input.ip, nameservers: servers, ok: true, records: await reverse(input.ip, servers) };
  } catch (error) {
    return {
      ip: input.ip,
      nameservers: servers,
      ok: false,
      code: errnoCode(error),
      message: errnoMessage(error)
    };
  }
}

export function txtStrings(records: DnsRecords | undefined): string[] {
  if (!Array.isArray(records)) return [];
  return records.flatMap((row) => {
    if (typeof row === "string") return [row];
    if (Array.isArray(row)) return [row.map(String).join("")];
    if (isRecord(row) && typeof row.data === "string") return [row.data];
    return [];
  });
}

export function stringRecords(records: DnsRecords | undefined): string[] {
  if (!Array.isArray(records)) return [];
  return records.flatMap((item) => (typeof item === "string" ? [item] : []));
}

export function mxExchanges(records: DnsRecords | undefined): string[] {
  if (!Array.isArray(records)) return [];
  const out: string[] = [];
  for (const item of records) {
    if (typeof item === "string" && item.length > 0) out.push(item);
    else {
      const rec = asRecord(item);
      const exchange = rec === undefined ? undefined : asString(rec.exchange);
      if (exchange !== undefined) out.push(exchange);
    }
  }
  return out;
}

export function readSoaSerial(records: DnsRecords | undefined): number | undefined {
  const rec = asRecord(records);
  return rec === undefined ? undefined : asFiniteNumber(rec.serial);
}
