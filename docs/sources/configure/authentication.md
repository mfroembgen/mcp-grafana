---
title: Authentication
menuTitle: Authentication
description: Authenticate the Grafana MCP server to Grafana using a service account token or username and password.
keywords:
  - authentication
  - service account
  - token
  - MCP
weight: 1
aliases:
  - /docs/grafana-cloud/machine-learning/mcp/configure/authentication/
---

# Authentication

The Grafana MCP server needs credentials to call the Grafana API. Use a service account token (recommended) or a username and password.

## What you'll achieve

You set the environment variables (or equivalent) so the server can authenticate to your Grafana instance. The same credentials apply whether you run the server with uvx, Docker, a binary, or Helm.

## Before you begin

- A Grafana instance (Grafana 9.0 or later).
- For token auth: a [service account](https://grafana.com/docs/grafana/latest/administration/service-accounts/#add-a-token-to-a-service-account-in-grafana) with a token and the RBAC permissions needed for the tools you use.

## Use a service account token

Set `GRAFANA_URL` and `GRAFANA_SERVICE_ACCOUNT_TOKEN` in the environment passed to the server.

- **GRAFANA_URL:** Your Grafana base URL (for example, `http://localhost:3000` or `https://myinstance.grafana.net`).
- **GRAFANA_SERVICE_ACCOUNT_TOKEN:** The token you created for the service account.

The deprecated `GRAFANA_API_KEY` is still supported but will be removed in a future version; use `GRAFANA_SERVICE_ACCOUNT_TOKEN` instead.

### Read the token from a file

Set `GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE` to a file path that contains the token instead of passing the value inline. The file is read fresh on every request, so a rotated token is picked up automatically without restarting the server.

This is useful in Kubernetes, where a Secret mounted as a volume is updated in place when the underlying Secret changes. Because the server's client cache is keyed on the token value, a rotated token transparently produces a new client with no pod restart:

```yaml
env:
  - name: GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE
    value: /var/run/secrets/grafana/token
volumeMounts:
  - name: grafana-token
    mountPath: /var/run/secrets/grafana
    readOnly: true
volumes:
  - name: grafana-token
    secret:
      secretName: grafana-mcp-token
```

Surrounding whitespace (including a trailing newline) is trimmed from the file contents. If both `GRAFANA_SERVICE_ACCOUNT_TOKEN` and `GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE` are set, the inline token takes precedence.

For HTTP deployments that [select a Grafana URL per request](../command-line-flags/#select-a-grafana-url-per-request), each request must supply a token for its selected instance. The server does not reuse `GRAFANA_SERVICE_ACCOUNT_TOKEN` or the token file for that request.

## Use username and password

You can use basic auth by setting `GRAFANA_USERNAME` and `GRAFANA_PASSWORD` instead of a token. This is less suitable for automation; prefer a service account token when possible.

## Authenticate MCP callers with WorkOS

Streamable HTTP can use [WorkOS AuthKit and Connect](https://workos.com/docs/authkit/mcp) for browser sign-in, consent and token refresh. This authenticates callers separately from the fixed Grafana credentials above. Use a Grafana Viewer service account with `--disable-write` for read-only access.

Configure the exact public MCP endpoint as a WorkOS Resource Indicator, enable CIMD and DCR for your MCP clients, and configure your sign-in provider in WorkOS. Then start the server with all three flags:

```bash
mcp-grafana --transport=streamable-http --disable-write \
  --allowed-hosts=mcp.example.com \
  --workos-authkit-domain=https://auth.example.com \
  --workos-resource-url=https://mcp.example.com/mcp \
  --workos-allowed-email-domain=example.com
```

Terminate TLS at the ingress or use the server TLS flags. The resource URL's path must match the configured MCP endpoint, including any `--base-path`. MCP clients connect to that URL and discover WorkOS automatically; the server needs no WorkOS API key or client secret.

Only RS256 Connect user grants for that exact issuer and resource are accepted. The server requires `openid` and `email`, then checks WorkOS userinfo using the same token: the subject must match, the email must be verified, and its domain must match the configured domain exactly. Profile responses are not cached. Existing grants remain subject to WorkOS expiry and revocation; suspending an upstream identity does not by itself revoke every existing grant.

WorkOS mode rejects partial configuration, static caller tokens, SSE/stdio, URL overrides, dynamic multi-org, and caller-header forwarding with `GRAFANA_FORWARD_HEADERS`. It strips caller credentials and all `X-Grafana-*` headers before tool execution, so callers use the server's configured Grafana identity. Without WorkOS flags, existing static-token and stdio behavior is unchanged.

## Next steps

- [Enable and disable tools](../enable-and-disable-tools/) to control which MCP tools are available.
- [Transports and addresses](../transports-and-addresses/) for stdio, SSE, and streamable-http.
