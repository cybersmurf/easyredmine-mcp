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

Create a `.env` based on `.env.example`:

```bash
cp .env.example .env
# then edit values
```

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

### Practical examples

List last 5 issues (sorted by update desc):

```json
{
  "query": { "limit": 5, "sort": "updated_on:desc" }
}
```

Get single issue (e.g., id 18944):

```json
{
  "pathParams": { "id": 18944, "format": "json" }
}
```

## Integrating with MCP clients
Configure your MCP client to launch this server via Node (stdio):
- Command: `node dist/index.js` (or `npm run dev` during development)
- Transport: stdio
- Env: set `REDMINE_BASE_URL`, `REDMINE_API_KEY`

### Example: Windsurf/Codeium mcp_config.json snippet

```json
{
  "mcpServers": {
    "redmine-openapi": {
      "command": "pwsh",
      "args": [
        "-NoProfile",
        "-Command",
        "Set-Location -Path 'J:\\GIT\\mcp-redmine\\CascadeProjects\\windsurf-project'; npm run dev"
      ],
      "env": {
        "REDMINE_BASE_URL": "https://your-redmine.example.com/",
        "REDMINE_API_KEY": "<your_api_key>",
        "REDMINE_INSECURE_SSL": "false"
      },
      "disabled": false
    }
  }
}
```

Note: You can keep secrets in a local `.env` and rely on `dotenv` instead of putting them directly in the client config.

## Troubleshooting

- Self-signed TLS: set `REDMINE_INSECURE_SSL=true` (development only).
- Missing `format`: server auto-injects `{format:"json"}` for paths containing `{format}`.
- GET payload: if you mistakenly send GET params in `body`, the server treats them as `query`.
- Base URL: If `REDMINE_BASE_URL` is empty, server tries `servers[0].url` from `openapi.json`.
