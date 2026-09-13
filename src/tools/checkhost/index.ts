import { z } from "zod";
import { defineTool, runTool } from "../../mcp/define-tool.js";
import {
  createCheckHostClient,
  fetchCheckHostResult,
  listCheckHostNodes,
  startCheckHost,
  waitCheckHostResult,
  type CheckHostType
} from "../../network/checkhost.js";
import { waitField, waitTimeoutMsField } from "../fields.js";

const nodes = z.array(z.string()).optional();
const maxNodes = z.number().int().min(1).max(50).optional();

function checkTool(type: CheckHostType, title: string, description: string, hostHelp: string) {
  return defineTool(
    `checkhost_${type}`,
    title,
    description,
    z.object({
      host: z.string().min(1).describe(hostHelp),
      maxNodes,
      nodes,
      wait: waitField,
      waitTimeoutMs: waitTimeoutMsField
    }),
    (_ctx, input) =>
      runTool(_ctx, async () => {
        const client = createCheckHostClient();
        const started = await startCheckHost(client, type, input.host, {
          ...(input.maxNodes === undefined ? {} : { maxNodes: input.maxNodes }),
          ...(input.nodes === undefined ? {} : { nodes: input.nodes })
        });
        if (input.wait === false) return started;
        const results = await waitCheckHostResult(
          client,
          started.request_id,
          input.waitTimeoutMs ?? 20_000
        );
        return { ...started, results };
      })
  );
}

export const tools = [
  defineTool(
    "checkhost_nodes",
    "Check-Host nodes",
    "List Check-Host probe nodes.",
    z.object({}),
    (ctx) => runTool(ctx, () => listCheckHostNodes(createCheckHostClient()))
  ),
  checkTool("ping", "Check-Host ping", "ICMP ping from Check-Host nodes.", "Hostname or IP."),
  checkTool("http", "Check-Host HTTP", "HTTP fetch from Check-Host nodes.", "Hostname, URL, or IP."),
  checkTool(
    "tcp",
    "Check-Host TCP",
    "TCP connect from Check-Host nodes.",
    "host:port or a URL such as https://example.com"
  ),
  checkTool("udp", "Check-Host UDP", "UDP probe from Check-Host nodes.", "host:port"),
  checkTool("dns", "Check-Host DNS", "DNS from Check-Host nodes.", "Hostname."),
  defineTool(
    "checkhost_result",
    "Check-Host result",
    "Fetch a Check-Host check by request id.",
    z.object({ requestId: z.string().min(1) }),
    (ctx, input) => runTool(ctx, () => fetchCheckHostResult(createCheckHostClient(), input.requestId))
  )
];
