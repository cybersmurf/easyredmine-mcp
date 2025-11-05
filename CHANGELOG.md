# Changelog

## v0.1.0 - 2025-11-05

- Initial public release.
- MCP server generated from Easy Redmine OpenAPI at runtime.
- Features:
  - Base URL fallback from OpenAPI servers[0].url
  - Auto-inject `{format: "json"}` when path requires it
  - Treat GET `body` as `query` for convenience
  - Optional insecure TLS via `REDMINE_INSECURE_SSL=true`
  - Better fetch error messages with URL
- Docs: README with MCP client snippet, .env.example
- CI: basic build (tsc) GitHub Actions
