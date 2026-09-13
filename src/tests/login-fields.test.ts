import { describe, expect, it } from "vitest";
import { collectLoginBag } from "../auth/fields.js";
import { loginFields } from "../auth/login-fields.js";
import { isAllowedRedirect } from "../auth/redirects.js";

describe("network login fields", () => {
  it("does not require a Check-Host token", () => {
    const names = loginFields().map((field) => field.name);
    expect(names).toEqual(["nameservers", "accountLabel"]);
    expect(loginFields().find((field) => field.name === "nameservers")?.secret).toBe(false);
    const result = collectLoginBag(loginFields(), {}, {});
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.bag.secrets).toEqual({});
  });

  it("stores nameservers as a claim", () => {
    const result = collectLoginBag(loginFields(), { nameservers: "8.8.8.8, 1.1.1.1" }, {});
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected ok");
    expect(result.bag.claims.nameservers).toBe("8.8.8.8, 1.1.1.1");
  });
});

describe("redirect allowlist", () => {
  it("allows Grok, Cursor loopback, and the Cursor native callback", () => {
    expect(isAllowedRedirect("https://grok.com/connectors-oauth-exchange-code/")).toBe(true);
    expect(isAllowedRedirect("http://localhost:8787/callback")).toBe(true);
    expect(isAllowedRedirect("cursor://anysphere.cursor-mcp/oauth/callback")).toBe(true);
    expect(isAllowedRedirect("cursor://evil.example/oauth/callback")).toBe(false);
    expect(isAllowedRedirect("https://evil.example/login")).toBe(false);
  });
});
