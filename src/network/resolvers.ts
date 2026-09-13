import { isIP } from "node:net";

export const DEFAULT_NAMESERVERS = ["1.1.1.1", "1.0.0.1"] as const;

export function parseNameservers(value: string | readonly string[] | undefined): string[] {
  let raw: string[];
  if (value === undefined) raw = [...DEFAULT_NAMESERVERS];
  else if (typeof value === "string") {
    raw = value.trim().length === 0 ? [...DEFAULT_NAMESERVERS] : value.split(/[\s,;]+/);
  } else {
    raw = value.flatMap((item) => item.split(/[\s,;]+/));
  }
  const servers = raw.map((item) => item.trim()).filter((item) => item.length > 0);
  if (servers.length === 0) return [...DEFAULT_NAMESERVERS];
  for (const server of servers) {
    const host = server.includes("]") ? server.slice(1, server.indexOf("]")) : server.split(":")[0] ?? server;
    if (isIP(host) === 0) {
      throw new Error(`Nameserver must be an IP address: ${server}`);
    }
  }
  return servers;
}

export function nameserversFromBag(
  claims: Readonly<Record<string, string>>,
  override?: string | readonly string[]
): string[] {
  if (override !== undefined) return parseNameservers(override);
  return parseNameservers(claims.nameservers);
}
