package main

import (
	"testing"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"
	"github.com/stretchr/testify/require"
)

func TestWorkOSCallerConfiguration(t *testing.T) {
	t.Setenv(serverAuthTokenEnvVar, "")
	for _, name := range []string{"GRAFANA_FORWARD_HEADERS", "GRAFANA_EXTRA_HEADERS", "GRAFANA_URL", "GRAFANA_API_KEY",
		"GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE", "GRAFANA_USERNAME", "GRAFANA_PASSWORD"} {
		t.Setenv(name, "")
	}
	t.Setenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "fixture-token")
	configured := callerAuthConfig{
		workosAuthkit: "https://auth.example.com", workosResource: "https://mcp.example.com/mcp",
		workosEmailDomain: "example.com",
	}
	with := func(change func(*callerAuthConfig)) callerAuthConfig {
		ca := configured
		change(&ca)
		return ca
	}

	auth, err := configured.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
	require.NoError(t, err)
	require.NotNil(t, auth)
	for name, config := range map[string]callerAuthConfig{
		"static": {token: "static-token"}, "stdio": {},
	} {
		auth, err := config.workOS(name, "/mcp", mcpgrafana.GrafanaConfig{})
		require.NoError(t, err)
		require.Nil(t, auth)
	}

	rejected := []struct {
		name                string
		ca                  callerAuthConfig
		transport, endpoint string
		gc                  mcpgrafana.GrafanaConfig
	}{
		{name: "stdio", ca: configured, transport: "stdio", endpoint: "/mcp"},
		{name: "sse", ca: configured, transport: "sse", endpoint: "/mcp"},
		{name: "partial", ca: with(func(ca *callerAuthConfig) { ca.workosEmailDomain = "" })},
		{name: "static token", ca: with(func(ca *callerAuthConfig) { ca.token = "static-token" })},
		{name: "per-user mode", ca: with(func(ca *callerAuthConfig) { ca.requireUserCredentials = true })},
		{name: "other endpoint", ca: configured, endpoint: "/other"},
		{name: "URL override", ca: configured, gc: mcpgrafana.GrafanaConfig{AllowGrafanaURLOverride: true}},
		{name: "URL allowlist", ca: configured, gc: mcpgrafana.GrafanaConfig{AllowedGrafanaURLs: []string{"https://grafana.example.com"}}},
		{name: "cross-origin redirects", ca: configured, gc: mcpgrafana.GrafanaConfig{AllowCrossOriginRedirects: true}},
		{name: "client certificate", ca: configured, gc: mcpgrafana.GrafanaConfig{TLSConfig: &mcpgrafana.TLSConfig{CertFile: "client.pem"}}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			transport, endpoint := tc.transport, tc.endpoint
			if transport == "" {
				transport = "streamable-http"
			}
			if endpoint == "" {
				endpoint = "/mcp"
			}
			_, err := tc.ca.workOS(transport, endpoint, tc.gc)
			require.Error(t, err)
		})
	}

	t.Run("user credential", func(t *testing.T) {
		t.Setenv("GRAFANA_USERNAME", "admin")
		_, err := configured.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
		require.ErrorContains(t, err, "service account token")
	})
	t.Run("extra headers", func(t *testing.T) {
		t.Setenv("GRAFANA_EXTRA_HEADERS", `{"X-WEBAUTH-USER":"admin"}`)
		_, err := configured.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
		require.ErrorContains(t, err, "GRAFANA_EXTRA_HEADERS")
	})
	t.Run("no credential", func(t *testing.T) {
		t.Setenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "")
		_, err := configured.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
		require.ErrorContains(t, err, "service account token")
	})

	previous := mcpgrafana.DynamicMultiOrgEnabled
	mcpgrafana.DynamicMultiOrgEnabled = true
	t.Cleanup(func() { mcpgrafana.DynamicMultiOrgEnabled = previous })
	_, err = configured.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
	require.Error(t, err)
}
