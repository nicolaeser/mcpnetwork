import { lookupSafe, nodeLookup, txtStrings, type LookupFn } from "./dns.js";
import { parseNameservers } from "./resolvers.js";

const DEFAULT_DKIM = ["google", "selector1", "selector2", "default", "k1", "s1", "s2", "dkim"] as const;

export interface DnsMailAuthReport {
  readonly domain: string;
  readonly nameservers: string[];
  readonly ok: boolean;
  readonly issues: string[];
  readonly spf: string[];
  readonly dmarc: string[];
  readonly bimi: string[];
  readonly dkim: Record<string, string[]>;
}

export async function dnsMailAuth(input: {
  readonly domain: string;
  readonly nameservers?: string | readonly string[];
  readonly dkimSelectors?: readonly string[];
  readonly lookup?: LookupFn;
}): Promise<DnsMailAuthReport> {
  const domain = input.domain.replace(/\.$/, "").toLowerCase();
  const servers = parseNameservers(input.nameservers);
  const lookup = input.lookup ?? nodeLookup;
  const selectors =
    input.dkimSelectors !== undefined && input.dkimSelectors.length > 0
      ? [...input.dkimSelectors]
      : [...DEFAULT_DKIM];
  const spfTxt = await lookupSafe(lookup, domain, "TXT", servers);
  const spf = txtStrings(spfTxt.ok ? spfTxt.records : undefined).filter((row) =>
    row.toLowerCase().startsWith("v=spf1")
  );
  const dmarcTxt = await lookupSafe(lookup, `_dmarc.${domain}`, "TXT", servers);
  const dmarc = txtStrings(dmarcTxt.ok ? dmarcTxt.records : undefined).filter((row) =>
    row.toLowerCase().startsWith("v=dmarc1")
  );
  const bimiTxt = await lookupSafe(lookup, `default._bimi.${domain}`, "TXT", servers);
  const bimi = txtStrings(bimiTxt.ok ? bimiTxt.records : undefined).filter((row) =>
    row.toLowerCase().startsWith("v=bimi1")
  );
  const dkim: Record<string, string[]> = {};
  for (const selector of selectors.slice(0, 8)) {
    const txt = await lookupSafe(lookup, `${selector}._domainkey.${domain}`, "TXT", servers);
    const records = txtStrings(txt.ok ? txt.records : undefined).filter((row) =>
      row.toLowerCase().includes("v=dkim1")
    );
    if (records.length > 0) dkim[selector] = records;
  }
  const issues: string[] = [];
  if (spf.length === 0) issues.push("No SPF TXT.");
  if (dmarc.length === 0) issues.push("No DMARC record at _dmarc.");
  return {
    domain,
    nameservers: servers,
    ok: issues.length === 0,
    issues,
    spf,
    dmarc,
    bimi,
    dkim
  };
}
