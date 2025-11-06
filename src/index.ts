import "dotenv/config";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import express, { type Request as ExRequest, type Response as ExResponse, type NextFunction as ExNextFunction } from "express";
import cors from "cors";
import { z } from "zod";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
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
  const params: any[] = Array.isArray(op.parameters) ? op.parameters : [];
  const pathParams = params.filter((pr) => pr && pr.in === "path");
  const queryParams = params.filter((pr) => pr && pr.in === "query");

  const pathParamProps: Record<string, any> = {};
  const pathParamRequired: string[] = [];
  for (const pr of pathParams) {
    const t = pr.schema?.type || "string";
    pathParamProps[pr.name] = { type: t, description: pr.description };
    if (pr.required) pathParamRequired.push(pr.name);
  }

  const queryProps: Record<string, any> = {};
  const queryRequired: string[] = [];
  for (const pr of queryParams) {
    const sch = pr.schema || {};
    let t = sch.type || "string";
    // normalize array type
    if (t === "array" && sch.items && sch.items.type) {
      t = "array";
      queryProps[pr.name] = { type: t, items: { type: sch.items.type }, description: pr.description };
    } else {
      queryProps[pr.name] = { type: t, description: pr.description };
    }
    if (pr.required) queryRequired.push(pr.name);
  }

  const schema: any = {
    type: "object",
    properties: {
      baseUrl: { type: "string", description: "Override base URL (defaults to env REDMINE_BASE_URL)" },
      apiKey: { type: "string", description: "Override API key (defaults to env REDMINE_API_KEY)" },
      apiKeyIn: { type: "string", enum: ["header", "query"], description: "Where to send API key (defaults to header)" },
      pathParams: {
        type: "object",
        properties: pathParamProps,
        additionalProperties: Object.keys(pathParamProps).length ? false : { type: ["string", "number", "boolean"] },
        ...(pathParamRequired.length ? { required: pathParamRequired } : {}),
      },
      query: {
        type: "object",
        properties: queryProps,
        additionalProperties: Object.keys(queryProps).length ? false : { type: ["string", "number", "boolean", "array", "null"] },
        ...(queryRequired.length ? { required: queryRequired } : {}),
      },
      headers: { type: "object", additionalProperties: { type: "string" } },
      body: { description: "Request body (JSON)", nullable: true },
    },
    additionalProperties: false,
    required: [],
  };
  if (pathParams.length) schema.required.push("pathParams");
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
  const debug = (process.env.DEBUG_MCP || "true").toLowerCase() === "true";
  if (debug) {
    // eslint-disable-next-line no-console
    console.log("[BOOT] MCP starting", {
      MCP_STDIO_ENABLED: process.env.MCP_STDIO_ENABLED,
      MCP_HTTP_ENABLED: process.env.MCP_HTTP_ENABLED,
    });
  }

  const defaultBaseUrl = process.env.REDMINE_BASE_URL || (spec.servers && spec.servers[0] ? spec.servers[0].url : "");
  const defaultApiKey = process.env.REDMINE_API_KEY || "";
  const { headerName, queryName } = detectDefaultAuth(spec);
  if (debug) {
    // eslint-disable-next-line no-console
    console.log("[BOOT] Defaults", {
      baseUrl: defaultBaseUrl,
      apiKeyPresent: Boolean(defaultApiKey),
      authHeader: headerName,
      authQuery: queryName,
    });
  }

  // Keep a registry of tools so we can expose an HTTP facade
  const toolRegistry: Array<{ name: string; description: string; inputSchema: any }> = [];
  const toolHandlers = new Map<string, (args: any) => Promise<{ content: Array<{ type: string; text?: string; json?: any }> }>>();
  const toolMeta = new Map<string, { pathTemplate: string; pathParams: string[] }>();

  for (const [p, methods] of Object.entries(spec.paths || {})) {
    for (const method of Object.keys(methods)) {
      const m = method.toLowerCase();
      if (!["get", "post", "put", "patch", "delete"].includes(m)) continue;
      const op = methods[method];
      const name = toToolName(m, p, op.operationId);
      const input = buildInputSchema(op);
      const requiredPath = (Array.isArray(op.parameters) ? op.parameters : []).filter((pr: any) => pr.in === "path" && pr.required).map((pr: any) => pr.name);
      const allPath = (Array.isArray(op.parameters) ? op.parameters : []).filter((pr: any) => pr.in === "path").map((pr: any) => pr.name);
      const allQuery = (Array.isArray(op.parameters) ? op.parameters : []).filter((pr: any) => pr.in === "query").map((pr: any) => pr.name);
      const baseDesc = op.summary || op.description || `${m.toUpperCase()} ${p}`;
      const description = `${baseDesc}\nMethod: ${m.toUpperCase()}\nPath: ${p}\nRequired path params: ${requiredPath.length ? requiredPath.join(", ") : "none"}\nPath params: ${allPath.length ? allPath.join(", ") : "none"}\nQuery params: ${allQuery.length ? allQuery.join(", ") : "none"}\nUsage: Provide 'pathParams' for path variables and 'query' for query string. Defaults: baseUrl from REDMINE_BASE_URL, apiKey from REDMINE_API_KEY.\nExample: { "pathParams": {${(allPath as string[]).map((n: string)=>` \"${n}\": "..."`).join(",")} }, "query": {${(allQuery as string[]).map((n: string)=>` \"${n}\": "..."`).join(",")} } }`;

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

      server.tool(name, description, argsSchema as any, async (a: any) => {
        const res = await handler(a);
        return res as any; // satisfy SDK type expectations
      });
      toolRegistry.push({ name, description, inputSchema: input });
      toolHandlers.set(name, handler);
      const requiredParams = Array.from(p.matchAll(/\{(.*?)\}/g)).map(m => m[1]);
      toolMeta.set(name, { pathTemplate: p, pathParams: requiredParams });
    }
  }
  if (debug) {
    // eslint-disable-next-line no-console
    console.log(`[BOOT] Registered tools: ${toolRegistry.length}`);
  }

  const issuesLatestSchema = z.object({
    limit: z.number().int().min(1).max(100).optional(),
    project_id: z.union([z.string(), z.number()]).optional(),
    status_id: z.union([z.string(), z.number()]).optional(),
    sort: z.string().optional()
  }).strict();

  server.tool(
    "issues_latest",
    "List latest Redmine issues. Returns up to 'limit' most recently updated issues. Usage: call with optional { limit, project_id, status_id, sort }. Default sort is 'updated_on:desc'.",
    issuesLatestSchema as any,
    async (args: any) => {
      const baseUrl = defaultBaseUrl;
      if (!baseUrl) throw new Error("Missing base URL. Set env REDMINE_BASE_URL or pass baseUrl.");
      const apiKey = defaultApiKey;
      const url = new URL("issues.json", baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
      url.searchParams.set("limit", String(args.limit ?? 5));
      url.searchParams.set("sort", String(args.sort ?? "updated_on:desc"));
      if (args.project_id != null) url.searchParams.set("project_id", String(args.project_id));
      if (args.status_id != null) url.searchParams.set("status_id", String(args.status_id));
      const headers: Record<string, string> = { Accept: "application/json" };
      if (apiKey) headers[headerName] = apiKey;
      const res = await fetch(url.toString(), { method: "GET", headers });
      const text = await res.text();
      let data: any = text;
      const ct = res.headers.get("content-type") || "";
      if (ct.includes("application/json")) {
        try { data = JSON.parse(text); } catch {}
      }
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}: ${typeof data === "string" ? data : JSON.stringify(data)}`);
      if (data && Array.isArray(data.issues)) {
        const items = (data.issues as any[]).map(it => ({
          id: it.id,
          subject: it.subject,
          project: it.project?.name,
          status: it.status?.name,
          updated_on: it.updated_on
        }));
        const out = JSON.stringify({ count: items.length, issues: items }, null, 2);
        return { content: [{ type: "text", text: out }] } as any;
      }
      const out = typeof data === "string" ? data : JSON.stringify(data, null, 2);
      return { content: [{ type: "text", text: out }] } as any;
    }
  );

  if ((process.env.MCP_STDIO_ENABLED || "true").toLowerCase() === "true") {
    if (debug) {
      // eslint-disable-next-line no-console
      console.log("[STDIO] Connecting STDIO transport...");
    }
    const transport = new StdioServerTransport();
    await server.connect(transport);
    if (debug) {
      // eslint-disable-next-line no-console
      console.log("[STDIO] STDIO transport connected");
    }
  } else if (debug) {
    // eslint-disable-next-line no-console
    console.log("[STDIO] Disabled via MCP_STDIO_ENABLED=false");
  }

  // Optional HTTP server for MCP over HTTP-like façade
  if ((process.env.MCP_HTTP_ENABLED || "false").toLowerCase() === "true") {
    const app = express();
    const port = Number(process.env.MCP_HTTP_PORT || 8080);
    const basePath = process.env.MCP_HTTP_PATH || "/mcp";
    const apiKey = process.env.MCP_HTTP_API_KEY || "";
    const corsOrigins = (process.env.MCP_CORS_ORIGINS || "*").split(",").map(s => s.trim());

    app.use(cors({ origin: corsOrigins.includes("*") ? true : corsOrigins }));
    app.use(express.json({ limit: "2mb" }));
    // Basic request logging
    app.use((req: ExRequest, _res: ExResponse, next: ExNextFunction) => {
      if (debug) {
        // eslint-disable-next-line no-console
        console.log(`[HTTP] ${req.method} ${req.url}`);
      }
      next();
    });

    // API key middleware (optional)
    app.use((req: ExRequest, res: ExResponse, next: ExNextFunction) => {
      if (!apiKey) return next();
      const provided = req.header("X-MCP-API-Key") || (req.query["api_key"] as string | undefined);
      if (provided === apiKey) return next();
      res.setHeader("WWW-Authenticate", 'ApiKey realm="MCP", header="X-MCP-API-Key"');
      res.status(401).json({ error: "Unauthorized" });
    });

    // Streamable HTTP endpoints using SDK transport
    const transports = new Map<string, StreamableHTTPServerTransport>();
    const isInitializeRequest = (body: any) => !!body && body.method === "initialize";

    // POST basePath: initialize or handle RPC
    app.post(`${basePath}`, async (req: ExRequest, res: ExResponse) => {
      const sid = String(req.header("MCP-Session-Id") || "");
      try {
        if (sid && transports.has(sid)) {
          const t = transports.get(sid)!;
          await t.handleRequest(req as any, res as any, req.body);
          return;
        }
        if (isInitializeRequest(req.body)) {
          const t = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
          t.onclose = () => {
            const id = (t as any).sessionId as string | undefined;
            if (id) transports.delete(id);
          };
          await server.connect(t);
          await t.handleRequest(req as any, res as any, req.body);
          const id = (t as any).sessionId as string | undefined;
          if (id) transports.set(id, t);
          return;
        }
        res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: No valid session ID provided" }, id: null });
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("MCP POST error:", e);
        if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      }
    });

    // GET basePath: SSE stream
    app.get(`${basePath}`, async (req: ExRequest, res: ExResponse) => {
      const sid = String(req.header("MCP-Session-Id") || "");
      if (!sid || !transports.has(sid)) {
        res.status(400).send("Invalid or missing session ID");
        return;
      }
      try {
        const t = transports.get(sid)!;
        await t.handleRequest(req as any, res as any);
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("MCP GET error:", e);
        if (!res.headersSent) res.status(500).send("Internal server error");
      }
    });

    // DELETE basePath: terminate
    app.delete(`${basePath}`, async (req: ExRequest, res: ExResponse) => {
      const sid = String(req.header("MCP-Session-Id") || "");
      if (!sid || !transports.has(sid)) {
        res.status(400).send("Invalid or missing session ID");
        return;
      }
      try {
        const t = transports.get(sid)!;
        await t.handleRequest(req as any, res as any);
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("MCP DELETE error:", e);
        if (!res.headersSent) res.status(500).send("Internal server error");
      }
    });

    // List tools metadata
    app.get(`${basePath}/tools`, (_req: ExRequest, res: ExResponse) => {
      res.json({ tools: toolRegistry });
    });

    // Call a tool by name (no id in URL)
    app.post(`${basePath}/call/:tool`, async (req: ExRequest, res: ExResponse) => {
      const tool = String(req.params.tool);
      const handler = toolHandlers.get(tool);
      if (!handler) return res.status(404).json({ error: `Unknown tool: ${tool}` });
      try {
        const meta = toolMeta.get(tool);
        const body = (req.body || {}) as any;
        const args: any = { ...body };
        if (Object.keys(req.query || {}).length) args.query = { ...(args.query || {}), ...req.query };
        if (meta && meta.pathParams.length) {
          args.pathParams = { ...(args.pathParams || {}) };
          for (const pp of meta.pathParams) {
            if (args.pathParams[pp] == null) {
              // from URL param
              if (req.params[pp] != null) args.pathParams[pp] = req.params[pp];
              // generic :id alias
              else if (pp === "id" && (req.params as any).id != null) args.pathParams[pp] = (req.params as any).id;
              // from body flat field
              else if (body[pp] != null) args.pathParams[pp] = body[pp];
              // from query string
              else if ((req.query as any)[pp] != null) args.pathParams[pp] = (req.query as any)[pp];
            }
          }
        }
        if (debug) {
          // eslint-disable-next-line no-console
          console.log(`[CALL] ${tool}`, {
            pathParams: Object.keys(args.pathParams || {}),
            query: Object.keys(args.query || {}),
            hasBody: args.body !== undefined,
          });
        }
        const result = await handler(args);
        res.json({ ok: true, result });
      } catch (err: any) {
        res.status(500).json({ ok: false, error: err?.message || String(err) });
      }
    });

    // Call a tool by name with :id passthrough
    app.post(`${basePath}/call/:tool/:id`, async (req: ExRequest, res: ExResponse) => {
      const tool = String(req.params.tool);
      const handler = toolHandlers.get(tool);
      if (!handler) return res.status(404).json({ error: `Unknown tool: ${tool}` });
      try {
        const meta = toolMeta.get(tool);
        const body = (req.body || {}) as any;
        const args: any = { ...body };
        if (Object.keys(req.query || {}).length) args.query = { ...(args.query || {}), ...req.query };
        if (meta && meta.pathParams.length) {
          args.pathParams = { ...(args.pathParams || {}) };
          for (const pp of meta.pathParams) {
            if (args.pathParams[pp] == null) {
              if (req.params[pp] != null) args.pathParams[pp] = req.params[pp];
              else if (pp === "id" && req.params.id != null) args.pathParams[pp] = req.params.id;
              else if (body[pp] != null) args.pathParams[pp] = body[pp];
              else if ((req.query as any)[pp] != null) args.pathParams[pp] = (req.query as any)[pp];
            }
          }
        }
        if (debug) {
          // eslint-disable-next-line no-console
          console.log(`[CALL] ${tool} (with :id)`, {
            pathParams: Object.keys(args.pathParams || {}),
            query: Object.keys(args.query || {}),
            hasBody: args.body !== undefined,
          });
        }
        const result = await handler(args);
        res.json({ ok: true, result });
      } catch (err: any) {
        res.status(500).json({ ok: false, error: err?.message || String(err) });
      }
    });

    // Root-level aliases for Open WebUI compatibility
    app.get(`/tools`, (_req: ExRequest, res: ExResponse) => {
      res.json({ tools: toolRegistry });
    });

    app.post(`/call/:tool`, async (req: ExRequest, res: ExResponse) => {
      const tool = String(req.params.tool);
      const handler = toolHandlers.get(tool);
      if (!handler) return res.status(404).json({ error: `Unknown tool: ${tool}` });
      try {
        const meta = toolMeta.get(tool);
        const body = (req.body || {}) as any;
        const args: any = { ...body };
        if (Object.keys(req.query || {}).length) args.query = { ...(args.query || {}), ...req.query };
        if (meta && meta.pathParams.length) {
          args.pathParams = { ...(args.pathParams || {}) };
          for (const pp of meta.pathParams) {
            if (args.pathParams[pp] == null) {
              if (req.params[pp] != null) args.pathParams[pp] = req.params[pp];
              else if (pp === "id" && req.params.id != null) args.pathParams[pp] = req.params.id;
              else if (body[pp] != null) args.pathParams[pp] = body[pp];
              else if ((req.query as any)[pp] != null) args.pathParams[pp] = (req.query as any)[pp];
            }
          }
        }
        const result = await handler(args);
        res.json({ ok: true, result });
      } catch (err: any) {
        res.status(500).json({ ok: false, error: err?.message || String(err) });
      }
    });

    app.post(`/call/:tool/:id`, async (req: ExRequest, res: ExResponse) => {
      const tool = String(req.params.tool);
      const handler = toolHandlers.get(tool);
      if (!handler) return res.status(404).json({ error: `Unknown tool: ${tool}` });
      try {
        const meta = toolMeta.get(tool);
        const body = (req.body || {}) as any;
        const args: any = { ...body };
        if (Object.keys(req.query || {}).length) args.query = { ...(args.query || {}), ...req.query };
        if (meta && meta.pathParams.length) {
          args.pathParams = { ...(args.pathParams || {}) };
          for (const pp of meta.pathParams) {
            if (args.pathParams[pp] == null) {
              if (req.params[pp] != null) args.pathParams[pp] = req.params[pp];
              else if (pp === "id" && req.params.id != null) args.pathParams[pp] = req.params.id;
              else if (body[pp] != null) args.pathParams[pp] = body[pp];
              else if ((req.query as any)[pp] != null) args.pathParams[pp] = (req.query as any)[pp];
            }
          }
        }
        const result = await handler(args);
        res.json({ ok: true, result });
      } catch (err: any) {
        res.status(500).json({ ok: false, error: err?.message || String(err) });
      }
    });

    app.get(`/health`, (_req: ExRequest, res: ExResponse) => {
      res.json({ status: "ok" });
    });

    // OpenAPI for the HTTP façade (per-tool paths with input schema)
    app.get(`${basePath}/openapi.json`, (_req: ExRequest, res: ExResponse) => {
      const servers = [{ url: `${process.env.MCP_PUBLIC_BASE || `http://localhost:${port}`}${basePath}` }];
      const paths: Record<string, any> = {
        "/tools": {
          get: { summary: "List available tools", responses: { "200": { description: "OK" } } }
        },
        "/call/{tool}": {
          post: {
            summary: "Call a tool by name (generic)",
            parameters: [ { name: "tool", in: "path", required: true, schema: { type: "string" } } ],
            requestBody: { required: false, content: { "application/json": { schema: { type: "object", additionalProperties: true } } } },
            responses: { "200": { description: "OK" } }
          }
        }
      };
      const components: Record<string, any> = { schemas: {} };
      for (const t of toolRegistry) {
        // Add component schema for the tool input
        components.schemas[t.name] = t.inputSchema || { type: "object", additionalProperties: true };
        // Add specific path for this tool name
        paths[`/call/${t.name}`] = {
          post: {
            summary: `Call tool ${t.name}`,
            requestBody: {
              required: false,
              content: {
                "application/json": {
                  schema: { $ref: `#/components/schemas/${t.name}` }
                }
              }
            },
            responses: { "200": { description: "OK" } }
          }
        };
      }
      const httpSpec = { openapi: "3.0.0", info: { title: "Redmine MCP HTTP", version: "0.1.0" }, servers, paths, components };
      res.json(httpSpec);
    });

    // Root-level OpenAPI alias for clients expecting /openapi.json at server root (OpenAPI 3.1.0)
    app.get(`/openapi.json`, (_req: ExRequest, res: ExResponse) => {
      const servers = [{ url: `${process.env.MCP_PUBLIC_BASE || `http://localhost:${port}`}` }];
      const paths: Record<string, any> = {};

      // System endpoints
      paths["/health"] = {
        get: {
          tags: ["System"],
          summary: "Health check",
          operationId: "health_check",
          responses: {
            "200": { description: "Successful Response", content: { "application/json": { schema: { type: "object" } } } }
          }
        }
      };
      paths["/tools"] = {
        get: {
          tags: ["System"],
          summary: "List available MCP tools",
          operationId: "list_tools",
          responses: {
            "200": { description: "Successful Response", content: { "application/json": { schema: { type: "object" } } } }
          }
        }
      };

      // Generic call endpoint
      paths["/call/{tool}"] = {
        post: {
          tags: ["System"],
          summary: "Call a tool by name (generic)",
          operationId: "call_tool_generic",
          parameters: [ { name: "tool", in: "path", required: true, schema: { type: "string" } } ],
          requestBody: { required: false, content: { "application/json": { schema: { type: "object", additionalProperties: true } } } },
          responses: {
            "200": { description: "Successful Response", content: { "application/json": { schema: { type: "object" } } } }
          }
        }
      };

      // Components and per-tool specific call endpoints
      const components: Record<string, any> = { schemas: {
        HTTPValidationError: {
          type: "object",
          title: "HTTPValidationError",
          properties: { detail: { type: "array", items: { $ref: "#/components/schemas/ValidationError" } } }
        },
        ValidationError: {
          type: "object",
          title: "ValidationError",
          required: ["loc", "msg", "type"],
          properties: {
            loc: { type: "array", items: { anyOf: [ { type: "string" }, { type: "integer" } ] }, title: "Location" },
            msg: { type: "string", title: "Message" },
            type: { type: "string", title: "Error Type" }
          }
        }
      } };

      for (const t of toolRegistry) {
        components.schemas[t.name] = t.inputSchema || { type: "object", additionalProperties: true };
        paths[`/call/${t.name}`] = {
          post: {
            tags: ["Tools"],
            summary: `Call tool ${t.name}`,
            operationId: `call_${t.name}`,
            requestBody: {
              required: false,
              content: {
                "application/json": {
                  schema: { $ref: `#/components/schemas/${t.name}` }
                }
              }
            },
            responses: {
              "200": { description: "Successful Response", content: { "application/json": { schema: { type: "object" } } } }
            }
          }
        };
      }

      const httpSpec = { openapi: "3.1.0", info: { title: "Redmine MCP HTTP (root)", version: "0.1.0" }, servers, paths, components };
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

export { main };
