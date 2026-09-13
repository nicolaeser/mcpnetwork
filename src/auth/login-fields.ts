import type { LoginField } from "./fields.js";

export function loginFields(): readonly LoginField[] {
  return [
    {
      name: "nameservers",
      label: "Default nameservers",
      type: "text",
      required: false,
      secret: false,
      envFallback: "MCPNETWORK_NAMESERVERS",
      prompt: "if-missing",
      placeholder: "1.1.1.1, 1.0.0.1",
      help: "Comma-separated DNS servers. Cloudflare 1.1.1.1 and 1.0.0.1 if empty."
    },
    {
      name: "accountLabel",
      prompt: "never",
      label: "Account label",
      type: "text",
      required: false,
      secret: false
    }
  ];
}

export function apiTokenFromBag(
  _bag: { readonly secrets: Readonly<Record<string, string>> },
  _envToken: string | undefined
): string | undefined {
  return undefined;
}
