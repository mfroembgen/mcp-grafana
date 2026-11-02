package mcpgrafana

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const workOSTestIssuer = "https://auth.example.com"
const workOSTestResource = "https://mcp.example.com/mcp"

type workOSTestTransport func(*http.Request) (*http.Response, error)

func (f workOSTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func workOSTestAuth(t *testing.T) (*WorkOSAuth, *rsa.PrivateKey) {
	t.Helper()
	t.Setenv("GRAFANA_FORWARD_HEADERS", "")
	a, err := NewWorkOSAuth(workOSTestIssuer, workOSTestResource, "example.com")
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return a, key
}

func workOSTestToken(t *testing.T, key *rsa.PrivateKey, changes jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": workOSTestIssuer, "aud": workOSTestResource,
		"sub": "user_test", "client_id": "client_test", "sid": "consent_test",
		"scope": "openid email", "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for name, value := range changes {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key1"
	raw, err := token.SignedString(key)
	require.NoError(t, err)
	return raw
}

func workOSTestJWKS(key *rsa.PublicKey, kid string) string {
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`,
		kid, base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()))
}

func workOSTestResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestWorkOSAuthTokenBoundary(t *testing.T) {
	a, key := workOSTestAuth(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var userinfo int
	a.client.Transport = workOSTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oauth2/jwks" {
			return workOSTestResponse(r, http.StatusOK, workOSTestJWKS(&key.PublicKey, "key1")), nil
		}
		userinfo++
		t.Fatal("invalid token reached userinfo")
		return nil, fmt.Errorf("unexpected request")
	})
	cases := map[string]jwt.MapClaims{
		"wrong issuer":         {"iss": "https://other.example.com"},
		"wrong audience":       {"aud": "https://other.example.com/mcp"},
		"audience array":       {"aud": []string{workOSTestResource}},
		"missing expiry":       {"exp": nil},
		"expired":              {"exp": time.Now().Add(-time.Minute).Unix()},
		"string expiry":        {"exp": "9999999999"},
		"fractional expiry":    {"exp": float64(time.Now().Add(time.Minute).Unix()) + 0.5},
		"future nbf":           {"nbf": time.Now().Add(time.Minute).Unix()},
		"string nbf":           {"nbf": "0"},
		"missing email scope":  {"scope": "openid"},
		"missing openid scope": {"scope": "email"},
		"M2M subject":          {"sub": "client_test"},
		"missing consent":      {"sid": nil},
		"missing client":       {"client_id": nil},
	}
	for name, changes := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := a.verify(t.Context(), workOSTestToken(t, key, changes), nil)
			require.Error(t, err)
		})
	}
	_, err = a.verify(t.Context(), workOSTestToken(t, otherKey, nil), nil)
	require.Error(t, err, "untrusted signature must fail")
	assert.Zero(t, userinfo)
}

func TestWorkOSAuthProfileAndCredentialBoundary(t *testing.T) {
	a, key := workOSTestAuth(t)
	raw := workOSTestToken(t, key, nil)
	const verified = `{"sub":"user_test","email":"reader@example.com","email_verified":true}`
	profile, status := verified, http.StatusOK
	userinfo := 0
	a.client.Transport = workOSTestTransport(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, workOSTestIssuer, r.URL.Scheme+"://"+r.URL.Host)
		if r.URL.Path == "/oauth2/jwks" {
			require.Empty(t, r.Header.Get("Authorization"))
			return workOSTestResponse(r, http.StatusOK, workOSTestJWKS(&key.PublicKey, "key1")), nil
		}
		userinfo++
		require.Equal(t, "/oauth2/userinfo", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer "+raw, r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("Cookie"))
		resp := workOSTestResponse(r, status, profile)
		resp.Header.Set("Location", "https://untrusted.example.com")
		return resp, nil
	})
	reached := false
	handler := a.Middleware(GrafanaURLOverrideMiddleware(false, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		for name := range r.Header {
			require.False(t, workOSCredentialHeader(name), "credential reached the MCP handler: %s", name)
		}
		assert.Equal(t, "2025-03-26", r.Header.Get("MCP-Protocol-Version"))
		w.WriteHeader(http.StatusOK)
	})))
	request := func() int {
		req := httptest.NewRequest(http.MethodPost, workOSTestResource, nil)
		for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Access-Token", "X-Grafana-URL", "X-Grafana-Service-Account-Token", "X-Grafana-API-Key", "X-Grafana-Org-Id", "X-Grafana-Id"} {
			req.Header.Set(name, "caller-override")
		}
		req.Header.Set("Authorization", "Bearer "+raw)
		req.Header.Set("MCP-Protocol-Version", "2025-03-26")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	require.Equal(t, http.StatusOK, request())
	require.True(t, reached)
	for _, invalid := range []string{
		`{"sub":"user_other","email":"reader@example.com","email_verified":true}`,
		`{"sub":"user_test","email":"reader@sub.example.com","email_verified":true}`,
		`{"sub":"user_test","email":"reader@example.com.evil","email_verified":true}`,
		`{"sub":"user_test","email":"a@b@example.com","email_verified":true}`,
		`{"sub":"user_test","email":"@example.com","email_verified":true}`,
		`{"sub":"user_test","email":"reader@example.com","email_verified":false}`,
		`{"sub":"user_test","email":"reader@example.com","email_verified":"true"}`,
		`{"sub":"user_test","email":"reader@example.com","email_verified":1}`,
		`{"sub":"user_test","email":"reader@example.com"}`,
		`[]`, `not JSON`, strings.Repeat(" ", 65<<10),
	} {
		t.Run(invalid[:min(len(invalid), 80)], func(t *testing.T) {
			profile, reached = invalid, false
			require.Equal(t, http.StatusUnauthorized, request())
			require.False(t, reached)
		})
	}
	profile = verified
	for _, failure := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable, http.StatusFound} {
		status, reached = failure, false
		before := userinfo
		require.Equal(t, http.StatusUnauthorized, request())
		require.False(t, reached)
		require.Equal(t, before+1, userinfo, "redirects must not be followed")
	}
	a.client.Transport = workOSTestTransport(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	require.Equal(t, http.StatusUnauthorized, request())
}

func TestWorkOSAuthDiscovery(t *testing.T) {
	a, _ := workOSTestAuth(t)
	mux := http.NewServeMux()
	mux.Handle("/mcp", a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated handler reached") })))
	a.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, workOSTestResource, nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, a.metadataURL, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &metadata))
	assert.Equal(t, workOSTestResource, metadata["resource"])
	assert.Equal(t, []any{workOSTestIssuer}, metadata["authorization_servers"])
}

func TestWorkOSAuthJWKSRotationAndRefreshBound(t *testing.T) {
	a, first := workOSTestAuth(t)
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks, requests := workOSTestJWKS(&first.PublicKey, "key1"), 0
	a.client.Transport = workOSTestTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		return workOSTestResponse(r, http.StatusOK, jwks), nil
	})
	_, err = a.publicKey(t.Context(), "key1")
	require.NoError(t, err)
	for _, kid := range []string{"unknown1", "unknown2"} {
		_, err = a.publicKey(t.Context(), kid)
		require.Error(t, err)
	}
	require.Equal(t, 1, requests)
	jwks, a.nextRefresh = workOSTestJWKS(&second.PublicKey, "key2"), time.Time{}
	rotated, err := a.publicKey(t.Context(), "key2")
	require.NoError(t, err)
	assert.Equal(t, second.N, rotated.N)
	assert.Equal(t, 2, requests)
	a.keysExpire, a.nextRefresh, jwks = time.Time{}, time.Time{}, `{"keys":[]}`
	_, err = a.publicKey(t.Context(), "key2")
	require.Error(t, err, "expired keys must not survive a failed refresh")
}

func TestWorkOSAuthCachedKeyDoesNotWaitForRefresh(t *testing.T) {
	a, key := workOSTestAuth(t)
	a.keys = map[string]*rsa.PublicKey{"key1": &key.PublicKey}
	a.keysExpire = time.Now().Add(time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	a.client.Transport = workOSTestTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-release
		return nil, context.DeadlineExceeded
	})
	refreshDone := make(chan error, 1)
	go func() {
		_, err := a.publicKey(ctx, "unknown")
		refreshDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("JWKS refresh did not start")
	}
	cached := make(chan *rsa.PublicKey, 1)
	go func() {
		public, _ := a.publicKey(ctx, "key1")
		cached <- public
	}()
	select {
	case public := <-cached:
		require.Equal(t, &key.PublicKey, public)
	case <-time.After(time.Second):
		t.Fatal("cached caller blocked on a JWKS network refresh")
	}
	close(release)
	require.Error(t, <-refreshDone)
}

func TestWorkOSAuthConfiguration(t *testing.T) {
	t.Setenv("GRAFANA_FORWARD_HEADERS", "")
	for _, value := range []struct{ issuer, resource, domain string }{
		{"", workOSTestResource, "example.com"},
		{"http://auth.example.com", workOSTestResource, "example.com"},
		{workOSTestIssuer + "/path", workOSTestResource, "example.com"},
		{workOSTestIssuer, workOSTestResource + "?query=1", "example.com"},
		{workOSTestIssuer, workOSTestResource, "*.example.com"},
		{workOSTestIssuer, workOSTestResource, "example.com/path"},
	} {
		_, err := NewWorkOSAuth(value.issuer, value.resource, value.domain)
		require.Error(t, err)
	}
	for _, name := range []string{"Authorization", "cookie", "X-Grafana-URL", "X-Grafana-Service-Account-Token", "X-Access-Token", "X-Api-Key", "X-Request-ID"} {
		t.Setenv("GRAFANA_FORWARD_HEADERS", name)
		_, err := NewWorkOSAuth(workOSTestIssuer, workOSTestResource, "example.com")
		require.Error(t, err)
	}
}

func TestWorkOSAuthRefreshSurvivesCallerCancellation(t *testing.T) {
	a, key := workOSTestAuth(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	a.client.Transport = workOSTestTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-release:
			if err := r.Context().Err(); err != nil {
				return nil, err
			}
			return workOSTestResponse(r, http.StatusOK, workOSTestJWKS(&key.PublicKey, "key1")), nil
		}
	})
	done := make(chan error, 1)
	go func() { _, err := a.publicKey(ctx, "unknown"); done <- err }()
	<-started
	cancel()
	close(release)
	<-done
	public, err := a.publicKey(t.Context(), "key1")
	require.NoError(t, err, "a disconnected caller must not prevent valid users from loading keys")
	require.Equal(t, &key.PublicKey, public)
}
