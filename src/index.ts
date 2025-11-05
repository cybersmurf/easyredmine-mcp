import "dotenv/config";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";
import express, { type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp";
import { z } from "zod";
import fs from "node:fs";
import path from "node:path";
if (process.env.REDMINE_INSECURE_SSL === "true") {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

// Types for a minimal subset of OpenAPI we need
interface OpenAPISpec {
  openapi: string;
  info: { title?: string; version?: string; description?: string };
  servers?: { url: string }[];
  components?: {
    securitySchemes?: Record<string, { type: string; name?: string; in?: string }>;
  };
  paths: Record<string, Record<string, any>>;
}

function loadOpenApiSpec(): OpenAPISpec {
  const file = path.resolve(process.cwd(), "openapi.json");
  const raw = fs.readFileSync(file, "utf-8");
  return JSON.parse(raw) as OpenAPISpec;
}

function toToolName(method: string, p: string, opId?: string): string {
  if (opId && /^[a-zA-Z0-9_.:-]+$/.test(opId)) return opId;
  const clean = p.replace(/\{|\}|\//g, "_").replace(/[^a-zA-Z0-9_]/g, "").replace(/_+/g, "_").replace(/^_+|_+$/g, "");
  return `${method.toLowerCase()}_${clean || "root"}`;
}

function buildInputSchema(op: any): any {
  const hasPathParams = Array.isArray(op.parameters) && op.parameters.some((pr: any) => pr.in === "path");
  const schema: any = {
    type: "object",
    properties: {
      baseUrl: { type: "string", description: "Override base URL (defaults to env REDMINE_BASE_URL)" },
      apiKey: { type: "string", description: "Override API key (defaults to env REDMINE_API_KEY)" },
      apiKeyIn: { type: "string", enum: ["header", "query"], description: "Where to send API key (defaults to header)" },
      pathParams: { type: "object", additionalProperties: { type: ["string", "number", "boolean"] } },
      query: { type: "object", additionalProperties: { type: ["string", "number", "boolean", "array", "null"] } },
      headers: { type: "object", additionalProperties: { type: "string" } },
      body: { description: "Request body (JSON)", nullable: true },
    },
    additionalProperties: false,
    required: [],
  };
  if (hasPathParams) schema.required.push("pathParams");
  return schema as any;
}

function substitutePath(p: string, pathParams: Record<string, any> | undefined): string {
  if (!pathParams) return p;
  return p.replace(/\{(.*?)\}/g, (_, k) => {
    const v = pathParams[k];
    if (v === undefined || v === null) throw new Error(`Missing path param: ${k}`);
    return encodeURIComponent(String(v));
  });
}

function buildUrl(baseUrl: string, p: string, query?: Record<string, any>): string {
  const url = new URL(p, baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null) continue;
      if (Array.isArray(v)) {
        v.forEach((vv) => url.searchParams.append(k, String(vv)));
      } else {
        url.searchParams.set(k, String(v));
      }
    }
  }
  return url.toString();
}

function detectDefaultAuth(spec: OpenAPISpec): { apiKeyIn: "header" | "query"; headerName: string; queryName: string } {
  const schemes = spec.components?.securitySchemes || {};
  let headerName = "X-Redmine-API-Key";
  let queryName = "key";
  let apiKeyIn: "header" | "query" = "header";
  for (const sch of Object.values(schemes)) {
    if (sch.type === "apiKey" && sch.in === "header" && sch.name) headerName = sch.name;
    if (sch.type === "apiKey" && sch.in === "query" && sch.name) queryName = sch.name;
  }
  return { apiKeyIn, headerName, queryName };
}

async function main() {
  const spec = loadOpenApiSpec();
  const server = new McpServer({ name: spec.info?.title || "Redmine OpenAPI MCP", version: spec.info?.version || "0.1.0" });

  const defaultBaseUrl = process.env.REDMINE_BASE_URL || (spec.servers && spec.servers[0] ? spec.servers[0].url : "");
  const defaultApiKey = process.env.REDMINE_API_KEY || "";
  const { headerName, queryName } = detectDefaultAuth(spec);

  // Keep a registry of tools so we can expose an HTTP facade
  const toolRegistry: Array<{ name: string; description: string; inputSchema: any }> = [];
  const toolHandlers = new Map<string, (args: any) => Promise<{ content: Array<{ type: string; text?: string; json?: any }> }>>();

  for (const [p, methods] of Object.entries(spec.paths || {})) {
    for (const method of Object.keys(methods)) {
      const m = method.toLowerCase();
      if (!["get", "post", "put", "patch", "delete"].includes(m)) continue;
      const op = methods[method];
      const name = toToolName(m, p, op.operationId);
      const description = op.summary || op.description || `${m.toUpperCase()} ${p}`;
      const input = buildInputSchema(op);

      // Build a permissive zod schema matching our expected args
      const argsSchema = z.object({
        baseUrl: z.string().optional(),
        apiKey: z.string().optional(),
        apiKeyIn: z.enum(["header", "query"]).optional(),
        pathParams: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
        query: z.record(z.any()).optional(),
        headers: z.record(z.string()).optional(),
        body: z.any().optional(),
      }).strict();

      const handler = async (args: any) => {
          const baseUrl = (args.baseUrl as string) || defaultBaseUrl;
          if (!baseUrl) throw new Error("Missing base URL. Set env REDMINE_BASE_URL or pass baseUrl.");

          const apiKey = (args.apiKey as string) || defaultApiKey;
          const apiKeyIn = (args.apiKeyIn as string) || "header";

          // Build URL
          const pp = { ...(args.pathParams || {}) } as Record<string, any>;
          if (p.includes("{format}") && (pp["format"] === undefined || pp["format"] === null)) {
            pp["format"] = "json";
          }
          const fullPath = substitutePath(p, pp);
          // Add API key in query if needed
          const query: Record<string, any> = { ...(args.query || {}) };
          // Backward-compat: if GET and caller passed body instead of query, use it as query
          if (m === "get" && !args.query && args.body && typeof args.body === "object") {
            Object.assign(query, args.body as Record<string, any>);
          }
          if (apiKey && apiKeyIn === "query") query[queryName] = apiKey;
          const url = buildUrl(baseUrl, fullPath, query);

          const headers: Record<string, string> = {
            Accept: "application/json",
            ...(args.headers || {}),
          };
          if (apiKey && apiKeyIn === "header") headers[headerName] = apiKey;
          if (["post", "put", "patch"].includes(m)) headers["Content-Type"] = headers["Content-Type"] || "application/json";

          let res: Response;
          try {
            res = await fetch(url, {
              method: m.toUpperCase(),
              headers,
              body: ["post", "put", "patch"].includes(m) && args.body !== undefined ? JSON.stringify(args.body) : undefined,
            });
          } catch (err: any) {
            throw new Error(`Fetch error for ${m.toUpperCase()} ${url}: ${err?.message || String(err)}`);
          }

          const text = await res.text();
          let data: any = text;
          const ct = res.headers.get("content-type") || "";
          if (ct.includes("application/json")) {
            try { data = JSON.parse(text); } catch {}
          }

          if (!res.ok) {
            throw new Error(`HTTP ${res.status} ${res.statusText}: ${typeof data === "string" ? data : JSON.stringify(data)}`);
          }

          // Return MCP CallToolResult (as text for maximum client compatibility)
          if (ct.includes("application/json")) {
            const textOut = typeof data === "string" ? data : JSON.stringify(data, null, 2);
            return { content: [{ type: "text", text: textOut }] };
          }
          return { content: [{ type: "text", text: typeof data === "string" ? data : String(data) }] };
      };

      server.tool(name, description, argsSchema.shape, handler);
      toolRegistry.push({ name, description, inputSchema: input });
      toolHandlers.set(name, handler);
    }
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Optional HTTP server for MCP over HTTP-like façade
  if ((process.env.MCP_HTTP_ENABLED || "false").toLowerCase() === "true") {
    const app = express();
    const port = Number(process.env.MCP_HTTP_PORT || 8080);
    const basePath = process.env.MCP_HTTP_PATH || "/mcp";
    const apiKey = process.env.MCP_HTTP_API_KEY || "";
    const corsOrigins = (process.env.MCP_CORS_ORIGINS || "*").split(",").map(s => s.trim());

    app.use(cors({ origin: corsOrigins.includes("*") ? true : corsOrigins }));
    app.use(express.json({ limit: "2mb" }));

    // API key middleware (optional)
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (!apiKey) return next();
      const provided = req.header("X-MCP-API-Key") || req.query["api_key"] as string | undefined;
      if (provided === apiKey) return next();
      res.status(401).json({ error: "Unauthorized" });
    });

    // List tools metadata
    app.get(`${basePath}/tools`, (_req: Request, res: Response) => {
      res.json({ tools: toolRegistry });
    });

    // Call a tool by name
    app.post(`${basePath}/call/:tool`, async (req: Request, res: Response) => {
      const tool = String(req.params.tool);
      const handler = toolHandlers.get(tool);
      if (!handler) return res.status(404).json({ error: `Unknown tool: ${tool}` });
      try {
        const result = await handler(req.body || {});
        res.json({ ok: true, result });
      } catch (err: any) {
        res.status(500).json({ ok: false, error: err?.message || String(err) });
      }
    });

    // Minimal OpenAPI for the HTTP façade
    app.get(`${basePath}/openapi.json`, (_req: Request, res: Response) => {
      const httpSpec = {
        openapi: "3.0.0",
        info: { title: "Redmine MCP HTTP", version: "0.1.0" },
        servers: [{ url: `${process.env.MCP_PUBLIC_BASE || `http://localhost:${port}`}${basePath}` }],
        paths: {
          "/tools": {
            get: {
              summary: "List available tools",
              responses: { "200": { description: "OK" } }
            }
          },
          "/call/{tool}": {
            post: {
              summary: "Call a tool by name",
              parameters: [ { name: "tool", in: "path", required: true, schema: { type: "string" } } ],
              requestBody: { required: false, content: { "application/json": { schema: { type: "object", additionalProperties: true } } } },
              responses: { "200": { description: "OK" } }
            }
          }
        }
      };
      res.json(httpSpec);
    });

    app.listen(port, () => {
      // eslint-disable-next-line no-console
      console.log(`MCP HTTP server listening on http://0.0.0.0:${port}${basePath}`);
    });
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
