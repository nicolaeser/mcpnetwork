import { describe, expect, it } from "vitest";
import { dnsCheckZone } from "../network/zone.js";
import { dnsCompare, PUBLIC_RESOLVER_GROUPS } from "../network/compare.js";
import { dnsMailAuth } from "../network/mail.js";
import { dnsReverse, type LookupFn, type RrType } from "../network/dns.js";
import { parseNameservers } from "../network/resolvers.js";
import { assertHttpUrl, probeHttp } from "../network/http-probe.js";
import { filterCrtName, parseCrtName, parseIssuance } from "../network/crt.js";
import { parseRdap } from "../network/rdap.js";
import { nextWhoisServer } from "../network/whois.js";
import { parseAbuse, parseGeo, parseNetwork, parseOverview, parseRpki } from "../network/ripe.js";
import { dohEndpoint } from "../network/doh.js";
import {
  DEFAULT_SSL_SETTINGS,
  evaluateSsl,
  nameMatchesSan,
  parseSubjectAltName,
  resolveSslSettings,
  type SslSnapshot
} from "../network/ssl.js";
import { TOOL_NAMES } from "../mcp/catalog.js";
import axios, { type AxiosAdapter, type InternalAxiosRequestConfig } from "axios";
import { AxiosHeaders } from "axios";

describe("nameservers", () => {
  it("defaults to Cloudflare", () => {
    expect(parseNameservers(undefined)).toEqual(["1.1.1.1", "1.0.0.1"]);
    expect(parseNameservers("")).toEqual(["1.1.1.1", "1.0.0.1"]);
  });

  it("splits a comma list and rejects hostnames", () => {
    expect(parseNameservers("1.1.1.1, 8.8.8.8")).toEqual(["1.1.1.1", "8.8.8.8"]);
    expect(() => parseNameservers("one.one.one.one")).toThrow(/IP address/);
  });
});

describe("zone check", () => {
  it("flags a CNAME at the apex and missing MX addresses", async () => {
    const lookup: LookupFn = async (name, type) => {
      const key = `${name}|${type as RrType}`;
      const table: Record<string, unknown> = {
        "example.com|SOA": { nsname: "ns1.example.com", hostmaster: "host.example.com", serial: 1 },
        "example.com|NS": ["ns1.example.com"],
        "ns1.example.com|A": ["203.0.113.1"],
        "ns1.example.com|AAAA": Object.assign(new Error("no AAAA"), { code: "ENODATA" }),
        "example.com|CNAME": ["elsewhere.example.net"],
        "example.com|MX": [{ exchange: "mail.example.com", priority: 10 }],
        "mail.example.com|A": Object.assign(new Error("no A"), { code: "ENODATA" }),
        "mail.example.com|AAAA": Object.assign(new Error("no AAAA"), { code: "ENODATA" }),
        "example.com|A": ["203.0.113.10"],
        "example.com|AAAA": Object.assign(new Error("no AAAA"), { code: "ENODATA" })
      };
      const hit = table[key];
      if (hit instanceof Error) throw hit;
      if (hit === undefined) throw Object.assign(new Error("nodata"), { code: "ENODATA" });
      return hit as never;
    };
    const report = await dnsCheckZone({ domain: "example.com", lookup });
    expect(report.ok).toBe(false);
    expect(report.issues).toEqual(
      expect.arrayContaining(["CNAME at zone apex.", "MX mail.example.com has no A/AAAA."])
    );
  });

  it("flags SOA serial mismatch across NS", async () => {
    const lookup: LookupFn = async (name, type, servers) => {
      if (name === "example.com" && type === "NS") return ["ns1.example.com", "ns2.example.com"];
      if (type === "A" && name.startsWith("ns")) return [name === "ns1.example.com" ? "203.0.113.1" : "203.0.113.2"];
      if (name === "example.com" && type === "SOA") {
        const serial = servers[0] === "203.0.113.2" ? 2 : 1;
        return { nsname: "ns1.example.com", hostmaster: "host.example.com", serial, refresh: 1, retry: 1, expire: 1, minttl: 1 };
      }
      throw Object.assign(new Error("nodata"), { code: "ENODATA" });
    };
    const report = await dnsCheckZone({ domain: "example.com", lookup });
    expect(report.serialsAgree).toBe(false);
    expect(report.issues).toContain("SOA serials differ across NS.");
  });
});

describe("dns compare", () => {
  it("appends extra resolvers to Cloudflare, Google, and Quad9", async () => {
    const seen: string[][] = [];
    const lookup: LookupFn = async (_name, _type, servers) => {
      seen.push([...servers]);
      return ["203.0.113.10"];
    };
    const report = await dnsCompare({ name: "example.com", extra: "4.4.4.4, 8.8.8.8", lookup });
    expect(report.agree).toBe(true);
    expect(seen).toEqual([...PUBLIC_RESOLVER_GROUPS.map((group) => [...group]), ["4.4.4.4"], ["8.8.8.8"]]);
  });
});

describe("dns reverse", () => {
  it("uses the injected reverse function for IPv6", async () => {
    const report = await dnsReverse({
      ip: "::1",
      reverse: async (ip) => {
        expect(ip).toBe("::1");
        return ["localhost"];
      }
    });
    expect(report).toEqual({ ip: "::1", nameservers: ["1.1.1.1", "1.0.0.1"], ok: true, records: ["localhost"] });
  });

  it("rejects a hostname", async () => {
    const report = await dnsReverse({ ip: "example.com" });
    expect(report.ok).toBe(false);
    if (report.ok) throw new Error("expected failure");
    expect(report.message).toMatch(/Not an IP address/);
  });
});

describe("mail auth", () => {
  it("collects SPF, DMARC, and a DKIM selector", async () => {
    const lookup: LookupFn = async (name, type) => {
      if (type !== "TXT") throw Object.assign(new Error("nodata"), { code: "ENODATA" });
      if (name === "example.com") return [["v=spf1 -all"]];
      if (name === "_dmarc.example.com") return [["v=DMARC1; p=reject;"]];
      if (name === "google._domainkey.example.com") return [["v=DKIM1; k=rsa; p=ab"]];
      throw Object.assign(new Error("nodata"), { code: "ENODATA" });
    };
    const report = await dnsMailAuth({ domain: "example.com", lookup });
    expect(report.ok).toBe(true);
    expect(report.spf).toEqual(["v=spf1 -all"]);
    expect(report.dmarc[0]).toMatch(/^v=DMARC1/i);
    expect(report.dkim.google).toEqual(["v=DKIM1; k=rsa; p=ab"]);
  });
});

describe("http probe", () => {
  it("rejects non-http URLs", () => {
    expect(() => assertHttpUrl("file:///etc/passwd")).toThrow(/http or https/);
    expect(() => assertHttpUrl("example.com")).toThrow(/http:\/\/ or https:\/\//);
  });

  it("records a redirect hop without following when disabled", async () => {
    const adapter: AxiosAdapter = async (config: InternalAxiosRequestConfig) => ({
      data: "",
      status: 301,
      statusText: "Moved",
      headers: AxiosHeaders.from({ location: "https://example.com/" }),
      config,
      request: {}
    });
    const report = await probeHttp({
      url: "https://example.org/",
      followRedirects: false,
      axiosInstance: axios.create({ adapter })
    });
    expect(report.ok).toBe(true);
    expect(report.hops).toHaveLength(1);
    expect(report.hops[0]?.status).toBe(301);
    expect(report.hops[0]?.location).toBe("https://example.com/");
    expect(report.followRedirects).toBe(false);
    expect(report.rejectUnauthorized).toBe(true);
  });
});

describe("crt.name", () => {
  it("parses rows and filters by contains and since", () => {
    const rows = parseCrtName([
      { sub: "www.example.com", first_seen: "2020-01-01T00:00:00Z" },
      { sub: "api.example.com", first_seen: "2024-06-01T00:00:00Z" },
      { sub: "*.example.com", first_seen: "2024-06-02T00:00:00Z" },
      "legacy.example.com"
    ]);
    const filtered = filterCrtName(rows, { contains: "api", since: "2024-01-01T00:00:00Z", limit: 10 });
    expect(filtered.total).toBe(1);
    expect(filtered.names[0]?.sub).toBe("api.example.com");
    expect(filterCrtName(rows, { limit: 10 }).wildcards).toBe(1);
  });

  it("parses a Cert Spotter issuance", () => {
    const [item] = parseIssuance({
      id: 12,
      dns_names: ["example.com"],
      not_before: "2025-01-01T00:00:00Z",
      not_after: "2026-01-01T00:00:00Z",
      revoked: false,
      cert_sha256: "abc",
      issuer: { friendly_name: "Sectigo" }
    });
    expect(item).toMatchObject({
      id: "12",
      dnsNames: ["example.com"],
      revoked: false,
      issuer: "Sectigo"
    });
  });
});

describe("rdap and ripe parsers", () => {
  it("extracts registrar and nameservers from RDAP", () => {
    const report = parseRdap("example.com", "domain", "/domain/example.com", {
      handle: "2336799",
      ldhName: "EXAMPLE.COM",
      status: ["client delete prohibited"],
      nameservers: [{ ldhName: "a.iana-servers.net" }],
      entities: [
        {
          roles: ["registrar"],
          vcardArray: ["vcard", [["fn", {}, "text", "RESERVED-IANA"]]]
        }
      ],
      events: [{ eventAction: "last changed", eventDate: "2024-01-01T00:00:00Z" }]
    });
    expect(report.registrar).toBe("RESERVED-IANA");
    expect(report.nameservers).toEqual(["a.iana-servers.net"]);
    expect(report.handle).toBe("2336799");
    expect(report.updated).toBe("2024-01-01T00:00:00Z");
    expect(report.expires).toBeNull();
  });

  it("follows IANA then registrar WHOIS referrals", () => {
    const iana = [
      "refer:        whois.verisign-grs.com",
      "domain:       COM",
      "whois:        whois.verisign-grs.com"
    ].join("\n");
    expect(nextWhoisServer(iana, "whois.iana.org")).toBe("whois.verisign-grs.com");
    const thin = [
      "Domain Name: EXAMPLE.COM",
      "Registrar WHOIS Server: whois.markmonitor.com",
      "Registrar: MarkMonitor Inc."
    ].join("\n");
    expect(nextWhoisServer(thin, "whois.verisign-grs.com")).toBe("whois.markmonitor.com");
    expect(nextWhoisServer(thin, "whois.markmonitor.com")).toBeUndefined();
  });

  it("parses RIPEstat payloads", () => {
    expect(parseNetwork({ asns: ["13335"], prefix: "1.1.1.0/24" })).toEqual({
      asns: ["13335"],
      prefix: "1.1.1.0/24"
    });
    expect(
      parseOverview({
        announced: true,
        resource: "1.1.1.0/24",
        asns: [{ asn: 13335, holder: "CLOUDFLARENET" }],
        block: { resource: "1.0.0.0/8" }
      }).asns
    ).toEqual([{ asn: 13335, holder: "CLOUDFLARENET" }]);
    expect(
      parseGeo({
        located_resources: [{ locations: [{ country: "?", city: "", latitude: 0, longitude: 0 }] }]
      }).country
    ).toBeNull();
    expect(parseAbuse({ abuse_contacts: ["abuse@example.net"], authoritative_rir: "apnic" }).contacts).toEqual([
      "abuse@example.net"
    ]);
    expect(parseRpki({ status: "valid", validator: "routinator", validating_roas: [{ origin: "13335", prefix: "1.1.1.0/24", validity: "valid", max_length: 24 }] }).status).toBe(
      "valid"
    );
  });
});

describe("ssl check", () => {
  const san = parseSubjectAltName("DNS:example.com, DNS:*.example.net, IP Address:203.0.113.10");

  it("parses SANs and matches names", () => {
    expect(san).toEqual({
      dns: ["example.com", "*.example.net"],
      ip: ["203.0.113.10"],
      email: []
    });
    expect(nameMatchesSan("example.com", san)).toBe(true);
    expect(nameMatchesSan("www.example.net", san)).toBe(true);
    expect(nameMatchesSan("a.b.example.net", san)).toBe(false);
    expect(nameMatchesSan("203.0.113.10", san)).toBe(true);
    expect(nameMatchesSan("evil.com", san)).toBe(false);
  });

  it("flags hostname mismatch, old protocol, and expiry", () => {
    const snapshot: SslSnapshot = {
      host: "evil.example",
      port: 443,
      sni: "evil.example",
      authorized: false,
      authorizationError: "self-signed certificate",
      protocol: "TLSv1.1",
      alpn: "http/1.1",
      cipher: { name: "RC4-SHA", standardName: "TLS_RSA_WITH_RC4_128_SHA", version: "TLSv1/SSLv3" },
      ocspStapled: false,
      hostnameMatch: false,
      certificate: {
        subject: "CN=example.com",
        issuer: "CN=example.com",
        validFrom: "2020-01-01T00:00:00.000Z",
        validTo: "2020-02-01T00:00:00.000Z",
        daysLeft: -10,
        fingerprint256: "ab",
        serialNumber: "1",
        san: { dns: ["example.com"], ip: [], email: [] },
        keyType: "rsa"
      },
      chain: []
    };
    const report = evaluateSsl(snapshot, 12);
    expect(report.ok).toBe(false);
    expect(report.issues.map((item) => item.code)).toEqual(
      expect.arrayContaining(["untrusted_chain", "hostname_mismatch", "old_protocol", "weak_cipher", "expired"])
    );
  });

  it("warns when the certificate expires soon", () => {
    const snapshot: SslSnapshot = {
      host: "example.com",
      port: 443,
      sni: "example.com",
      authorized: true,
      authorizationError: null,
      protocol: "TLSv1.3",
      alpn: "h2",
      cipher: { name: "TLS_AES_256_GCM_SHA384", standardName: "TLS_AES_256_GCM_SHA384", version: "TLSv1.3" },
      ocspStapled: true,
      hostnameMatch: true,
      certificate: {
        subject: "CN=example.com",
        issuer: "CN=Let's Encrypt",
        validFrom: "2026-01-01T00:00:00.000Z",
        validTo: "2026-09-20T00:00:00.000Z",
        daysLeft: 7,
        fingerprint256: "cd",
        serialNumber: "2",
        san: { dns: ["example.com"], ip: [], email: [] },
        keyType: "ec"
      },
      chain: []
    };
    const report = evaluateSsl(snapshot, 8);
    expect(report.ok).toBe(true);
    expect(report.issues).toEqual([
      expect.objectContaining({ severity: "warning", code: "expires_soon" })
    ]);
  });

  it("lets the caller skip hostname errors and disable expiry warnings", () => {
    const snapshot: SslSnapshot = {
      host: "evil.example",
      port: 443,
      sni: "evil.example",
      authorized: true,
      authorizationError: null,
      protocol: "TLSv1.3",
      alpn: "h2",
      cipher: { name: "TLS_AES_256_GCM_SHA384", standardName: "TLS_AES_256_GCM_SHA384", version: "TLSv1.3" },
      ocspStapled: true,
      hostnameMatch: false,
      certificate: {
        subject: "CN=example.com",
        issuer: "CN=Let's Encrypt",
        validFrom: "2026-01-01T00:00:00.000Z",
        validTo: "2026-09-20T00:00:00.000Z",
        daysLeft: 7,
        fingerprint256: "cd",
        serialNumber: "2",
        san: { dns: ["example.com"], ip: [], email: [] },
        keyType: "ec"
      },
      chain: []
    };
    const settings = resolveSslSettings({ checkHostname: false, expiryWarnDays: 0, rejectUnauthorized: true });
    const report = evaluateSsl(snapshot, 8, settings);
    expect(report.ok).toBe(true);
    expect(report.issues).toEqual([]);
    expect(report.settings).toMatchObject({
      checkHostname: false,
      expiryWarnDays: 0,
      rejectUnauthorized: true
    });
    expect(resolveSslSettings({}).rejectUnauthorized).toBe(DEFAULT_SSL_SETTINGS.rejectUnauthorized);
  });
});

describe("doh endpoints", () => {
  it("maps public resolvers to their JSON DoH URLs", () => {
    expect(dohEndpoint("1.1.1.1")).toContain("cloudflare-dns.com");
    expect(dohEndpoint("8.8.8.8")).toContain("dns.google");
    expect(dohEndpoint("9.9.9.9")).toContain("quad9");
    expect(dohEndpoint("203.0.113.1")).toContain("cloudflare-dns.com");
  });
});

describe("catalog", () => {
  it("registers the no-key tools", () => {
    expect(TOOL_NAMES).toEqual(
      expect.arrayContaining([
        "network_whoami",
        "dns_lookup",
        "dns_reverse",
        "dns_mail_auth",
        "dns_dnssec",
        "rdap_lookup",
        "ssl_check",
        "crt_subdomains",
        "crt_certs",
        "ip_info",
        "ip_abuse",
        "ip_rpki"
      ])
    );
  });
});
