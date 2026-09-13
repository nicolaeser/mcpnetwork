import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpServer } from "../mcp/server.js";
import { defaultClientFactory } from "../upstream/client.js";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";

export interface StdioRunOptions {
  readonly env?: NodeJS.ProcessEnv;
}

export async function runStdio(options: StdioRunOptions = {}): Promise<void> {
  const env = options.env ?? process.env;
  const nameservers = env.MCPNETWORK_NAMESERVERS;
  const server = createMcpServer({
    createClient: defaultClientFactory,
    getToken: () => "local",
    getBag: () => ({
      secrets: {},
      claims: {
        ...(nameservers === undefined || nameservers.length === 0 ? {} : { nameservers })
      }
    })
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${PACKAGE_NAME}/${PACKAGE_VERSION} listening on stdio\n`);
}
