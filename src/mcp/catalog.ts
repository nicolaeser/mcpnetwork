import { tools as account } from "../tools/account/index.js";
import { tools as dns } from "../tools/dns/index.js";
import { tools as probe } from "../tools/probe/index.js";
import { tools as checkhost } from "../tools/checkhost/index.js";
import { tools as crt } from "../tools/crt/index.js";
import { tools as ip } from "../tools/ip/index.js";

export const TOOL_CATALOG = [
  ...account,
  ...dns,
  ...probe,
  ...checkhost,
  ...crt,
  ...ip
];

export const TOOL_NAMES = TOOL_CATALOG.map((entry) => entry.name);
