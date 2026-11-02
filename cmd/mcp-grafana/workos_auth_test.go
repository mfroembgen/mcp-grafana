package main

import (
	"testing"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"
	"github.com/stretchr/testify/require"
)

func TestWorkOSCallerConfiguration(t *testing.T) {
	t.Setenv(serverAuthTokenEnvVar, "")
	t.Setenv("GRAFANA_FORWARD_HEADERS", "")
	configured := callerAuthConfig{
		workosAuthkit: "https://auth.example.com", workosResource: "https://mcp.example.com/mcp",
		workosEmailDomain: "example.com",
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
	for _, transport := range []string{"stdio", "sse"} {
		_, err := configured.workOS(transport, "/mcp", mcpgrafana.GrafanaConfig{})
		require.Error(t, err)
	}
	partial := configured
	partial.workosEmailDomain = ""
	_, err = partial.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
	require.Error(t, err)
	mixed := configured
	mixed.token = "static-token"
	_, err = mixed.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
	require.Error(t, err)
	_, err = configured.workOS("streamable-http", "/other", mcpgrafana.GrafanaConfig{})
	require.Error(t, err)
	for _, config := range []mcpgrafana.GrafanaConfig{
		{AllowGrafanaURLOverride: true}, {AllowedGrafanaURLs: []string{"https://grafana.example.com"}},
	} {
		_, err := configured.workOS("streamable-http", "/mcp", config)
		require.Error(t, err)
	}
	previous := mcpgrafana.DynamicMultiOrgEnabled
	mcpgrafana.DynamicMultiOrgEnabled = true
	t.Cleanup(func() { mcpgrafana.DynamicMultiOrgEnabled = previous })
	_, err = configured.workOS("streamable-http", "/mcp", mcpgrafana.GrafanaConfig{})
	require.Error(t, err)
}
