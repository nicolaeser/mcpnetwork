import axios, { type AxiosInstance } from "axios";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { asBoolean, asFiniteNumber, asRecord, asString, asStringArray, asUnknownArray } from "./shape.js";

export interface RipeNetworkInfo {
  readonly asns: string[];
  readonly prefix: string | null;
}

export interface RipeAsnHolder {
  readonly asn: number;
  readonly holder: string;
}

export interface RipePrefixOverview {
  readonly announced: boolean | null;
  readonly resource: string | null;
  readonly asns: RipeAsnHolder[];
  readonly block: string | null;
}

export interface RipeGeo {
  readonly country: string | null;
  readonly city: string | null;
  readonly latitude: number | null;
  readonly longitude: number | null;
}

export interface RipeAbuse {
  readonly contacts: string[];
  readonly authoritativeRir: string | null;
}

export interface RipeRoa {
  readonly origin: string | null;
  readonly prefix: string | null;
  readonly validity: string | null;
  readonly maxLength: number | null;
}

export interface RipeRpki {
  readonly status: string | null;
  readonly validator: string | null;
  readonly roas: RipeRoa[];
}

export interface IpInfoReport {
  readonly resource: string;
  readonly network: RipeNetworkInfo;
  readonly overview: RipePrefixOverview;
  readonly geo: RipeGeo;
}

export interface IpAbuseReport {
  readonly resource: string;
  readonly abuse: RipeAbuse;
}

export type IpRpkiReport =
  | {
      readonly resource: string;
      readonly asn: string;
      readonly prefix: string;
      readonly rpki: RipeRpki;
    }
  | {
      readonly resource: string;
      readonly network: RipeNetworkInfo;
      readonly message: string;
    };

export function createRipeClient(axiosInstance?: AxiosInstance): AxiosInstance {
  return (
    axiosInstance ??
    axios.create({
      baseURL: "https://stat.ripe.net",
      timeout: 15_000,
      headers: {
        Accept: "application/json",
        "User-Agent": `${PACKAGE_NAME}/${PACKAGE_VERSION}`
      }
    })
  );
}

export async function ripeData(
  client: AxiosInstance,
  name: string,
  params: Record<string, string>
): Promise<unknown> {
  const response = await client.get<unknown>(`/data/${name}/data.json`, { params });
  const body = asRecord(response.data) ?? {};
  const status = asString(body.status);
  if (status !== undefined && status !== "ok") {
    throw new Error(`RIPEstat ${name} status ${status}`);
  }
  return body.data ?? body;
}

export async function ipInfo(resource: string, axiosInstance?: AxiosInstance): Promise<IpInfoReport> {
  const client = createRipeClient(axiosInstance);
  const q = resource.trim();
  const [network, overview, geo] = await Promise.all([
    ripeData(client, "network-info", { resource: q }),
    ripeData(client, "prefix-overview", { resource: q }),
    ripeData(client, "maxmind-geo-lite", { resource: q })
  ]);
  return {
    resource: q,
    network: parseNetwork(network),
    overview: parseOverview(overview),
    geo: parseGeo(geo)
  };
}

export async function ipAbuse(resource: string, axiosInstance?: AxiosInstance): Promise<IpAbuseReport> {
  const client = createRipeClient(axiosInstance);
  const q = resource.trim();
  return { resource: q, abuse: parseAbuse(await ripeData(client, "abuse-contact-finder", { resource: q })) };
}

export async function ipRpki(resource: string, axiosInstance?: AxiosInstance): Promise<IpRpkiReport> {
  const client = createRipeClient(axiosInstance);
  const q = resource.trim();
  const network = parseNetwork(await ripeData(client, "network-info", { resource: q }));
  const asn = network.asns[0] ?? "";
  const prefix = network.prefix ?? "";
  if (asn.length === 0 || prefix.length === 0) {
    return { resource: q, network, message: "No ASN/prefix to validate." };
  }
  return {
    resource: q,
    asn,
    prefix,
    rpki: parseRpki(await ripeData(client, "rpki-validation", { resource: asn, prefix }))
  };
}

export function parseNetwork(value: unknown): RipeNetworkInfo {
  const rec = asRecord(value) ?? {};
  return { asns: asStringArray(rec.asns), prefix: asString(rec.prefix) ?? null };
}

export function parseOverview(value: unknown): RipePrefixOverview {
  const rec = asRecord(value) ?? {};
  const block = asRecord(rec.block);
  return {
    announced: asBoolean(rec.announced) ?? null,
    resource: asString(rec.resource) ?? null,
    asns: asUnknownArray(rec.asns).flatMap(parseAsnHolder),
    block: block === undefined ? null : (asString(block.resource) ?? asString(block.desc) ?? null)
  };
}

export function parseGeo(value: unknown): RipeGeo {
  const rec = asRecord(value) ?? {};
  const firstResource = asRecord(asUnknownArray(rec.located_resources)[0]);
  const firstLocation = asRecord(asUnknownArray(firstResource?.locations)[0]);
  if (firstLocation === undefined) {
    return { country: null, city: null, latitude: null, longitude: null };
  }
  const country = asString(firstLocation.country);
  return {
    country: country === "?" ? null : (country ?? null),
    city: asString(firstLocation.city) ?? null,
    latitude: asFiniteNumber(firstLocation.latitude) ?? null,
    longitude: asFiniteNumber(firstLocation.longitude) ?? null
  };
}

export function parseAbuse(value: unknown): RipeAbuse {
  const rec = asRecord(value) ?? {};
  return {
    contacts: asStringArray(rec.abuse_contacts),
    authoritativeRir: asString(rec.authoritative_rir) ?? null
  };
}

export function parseRpki(value: unknown): RipeRpki {
  const rec = asRecord(value) ?? {};
  return {
    status: asString(rec.status) ?? null,
    validator: asString(rec.validator) ?? null,
    roas: asUnknownArray(rec.validating_roas).flatMap((item) => {
      const row = asRecord(item);
      if (row === undefined) return [];
      return [
        {
          origin: asString(row.origin) ?? (asFiniteNumber(row.origin) !== undefined ? String(row.origin) : null),
          prefix: asString(row.prefix) ?? null,
          validity: asString(row.validity) ?? null,
          maxLength: asFiniteNumber(row.max_length) ?? null
        }
      ];
    })
  };
}

function parseAsnHolder(value: unknown): RipeAsnHolder[] {
  const rec = asRecord(value);
  if (rec === undefined) return [];
  const asn = asFiniteNumber(rec.asn);
  const holder = asString(rec.holder) ?? "";
  return asn === undefined ? [] : [{ asn, holder }];
}
