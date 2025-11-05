# Redmine OpenAPI MCP Server

MCP server that dynamically exposes Easy Redmine API operations as MCP tools, generated at runtime from `openapi.json`.

## Prerequisites
- Node.js 18.17+ (Node 18+ for built-in fetch)
- The `openapi.json` file in the project root (already present)

## Install
```bash
npm install
```

## Configuration
Set your Redmine base URL and API key. Two auth options are supported (as per OpenAPI securitySchemes):
- Header API key (default): `X-Redmine-API-Key`
- Query API key: `key`

Environment variables:
- `REDMINE_BASE_URL` e.g. `https://redmine.emistr.cz`
- `REDMINE_API_KEY` your API key

You can also override per-tool call with `baseUrl`, `apiKey`, and `apiKeyIn` ("header" | "query").

## Develop
```bash
npm run dev
```
This starts the MCP server over stdio.

## Build & Run
```bash
npm run build
npm start
```

## How it works
- Reads `openapi.json`
- Iterates all paths and HTTP methods (GET/POST/PUT/PATCH/DELETE)
- Creates an MCP tool per operation (name uses `operationId` if present)
- Tool input supports:
  - `pathParams` for templated segments like `{id}`
  - `query` for query string parameters
  - `headers` to add/override request headers
  - `body` for JSON payloads on write methods
  - `baseUrl`, `apiKey`, `apiKeyIn` for per-call overrides

## Example tool call (conceptual)
Input:
```json
{
  "pathParams": { "id": 123, "format": "json" },
  "query": { "limit": 25 },
  "headers": { "Accept": "application/json" }
}
```

## Integrating with MCP clients
Configure your MCP client to launch this server via Node (stdio):
- Command: `node dist/index.js` (or `npm run dev` during development)
- Transport: stdio
- Env: set `REDMINE_BASE_URL`, `REDMINE_API_KEY`
