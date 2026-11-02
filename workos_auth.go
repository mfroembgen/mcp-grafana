package mcpgrafana

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/sync/singleflight"
)

// WorkOSAuth validates Connect user grants for one fixed Grafana MCP resource.
// WorkOS handles client registration, browser sign-in, consent and refresh.
type WorkOSAuth struct {
	issuer, resource, emailDomain string
	metadataURL                   string
	client                        *http.Client
	mu                            sync.Mutex
	refresh                       singleflight.Group
	keys                          map[string]*rsa.PublicKey
	keysExpire, nextRefresh       time.Time
}

// NewWorkOSAuth requires an HTTPS AuthKit origin, an exact HTTPS MCP resource
// URL and the domain whose verified users may access the configured Grafana.
func NewWorkOSAuth(authkitDomain, resourceURL, allowedEmailDomain string) (*WorkOSAuth, error) {
	issuer, err := workOSHTTPSURL(strings.TrimSuffix(authkitDomain, "/"))
	if err != nil || issuer.Path != "" {
		return nil, fmt.Errorf("workos-authkit-domain must be an HTTPS origin without a path")
	}
	resource, err := workOSHTTPSURL(resourceURL)
	if err != nil || resource.Path == "" || resource.RawPath != "" {
		return nil, fmt.Errorf("workos-resource-url must be an exact HTTPS MCP endpoint URL")
	}
	domain, err := workOSHTTPSURL("https://" + allowedEmailDomain)
	if err != nil || domain.Hostname() != allowedEmailDomain || domain.Port() != "" || domain.Path != "" || strings.ContainsAny(allowedEmailDomain, "@*[]:\\ \t\r\n") {
		return nil, fmt.Errorf("workos-allowed-email-domain must be one exact domain")
	}
	if len(forwardHeaderNamesFromEnv()) != 0 {
		return nil, fmt.Errorf("WorkOS caller authentication cannot forward caller headers to Grafana")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	metadata := *resource
	metadata.Path = "/.well-known/oauth-protected-resource" + resource.Path
	return &WorkOSAuth{
		issuer: issuer.String(), resource: resource.String(), emailDomain: allowedEmailDomain,
		metadataURL: metadata.String(),
		client: &http.Client{
			Transport: transport, Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func workOSHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("invalid HTTPS URL")
	}
	return u, nil
}

// RegisterRoutes publishes public MCP discovery metadata. The resource URL is
// configured explicitly, never inferred from untrusted request headers.
func (a *WorkOSAuth) RegisterRoutes(mux *http.ServeMux) {
	u, _ := url.Parse(a.metadataURL)
	mux.Handle(u.Path, auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource: a.resource, AuthorizationServers: []string{a.issuer},
		ScopesSupported:        []string{"openid", "email", "profile", "offline_access"},
		BearerMethodsSupported: []string{"header"},
	}))
	// Compatibility with clients that discover the authorization server on the
	// resource origin instead of following protected resource metadata.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		body, err := a.request(r.Context(), http.MethodGet, a.issuer+"/.well-known/oauth-authorization-server", "")
		if err != nil || !json.Valid(body) {
			http.Error(w, "authorization server metadata unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// Middleware authenticates before any Grafana credential or target selection.
// Caller tokens and override headers never reach the MCP transport or Grafana.
func (a *WorkOSAuth) Middleware(next http.Handler) http.Handler {
	return auth.RequireBearerToken(a.verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: a.metadataURL, Scopes: []string{"openid", "email"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		for name := range r.Header {
			if workOSCredentialHeader(name) {
				delete(r.Header, name)
			}
		}
		next.ServeHTTP(w, r)
	}))
}

func workOSCredentialHeader(name string) bool {
	name = strings.ToLower(name)
	return name == "authorization" || name == "proxy-authorization" || name == "cookie" || name == "x-access-token" || strings.HasPrefix(name, "x-grafana-")
}

func (a *WorkOSAuth) verify(ctx context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if _, critical := t.Header["crit"]; !ok || kid == "" || critical {
			return nil, auth.ErrInvalidToken
		}
		return a.publicKey(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.resource), jwt.WithExpirationRequired(), jwt.WithJSONNumber())
	if err != nil || !token.Valid {
		return nil, auth.ErrInvalidToken
	}
	claims := token.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)
	client, _ := claims["client_id"].(string)
	sid, _ := claims["sid"].(string)
	scope, _ := claims["scope"].(string)
	scopes := strings.Fields(scope)
	exp, ok := claims["exp"].(json.Number)
	expires, expErr := exp.Int64()
	if claims["aud"] != a.resource || !strings.HasPrefix(sub, "user_") || client == "" || sid == "" ||
		!ok || expErr != nil || !slices.Contains(scopes, "openid") || !slices.Contains(scopes, "email") {
		return nil, auth.ErrInvalidToken
	}
	if rawNBF, present := claims["nbf"]; present {
		nbf, ok := rawNBF.(json.Number)
		if _, err := nbf.Int64(); !ok || err != nil {
			return nil, auth.ErrInvalidToken
		}
	}
	body, err := a.request(ctx, http.MethodPost, a.issuer+"/oauth2/userinfo", raw)
	var profile struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err != nil || json.Unmarshal(body, &profile) != nil {
		return nil, auth.ErrInvalidToken
	}
	local, domain, _ := strings.Cut(profile.Email, "@")
	if profile.Subject != sub || !profile.EmailVerified || local == "" || !strings.EqualFold(domain, a.emailDomain) {
		return nil, auth.ErrInvalidToken
	}
	// The SDK checks expiry again after the profile request before admitting it.
	return &auth.TokenInfo{UserID: sub, Scopes: scopes, Expiration: time.Unix(expires, 0)}, nil
}

func (a *WorkOSAuth) request(ctx context.Context, method, target, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WorkOS request failed")
	}
	const maxBody = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, fmt.Errorf("invalid WorkOS response")
	}
	return body, nil
}

func (a *WorkOSAuth) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key := a.cachedKey(kid); key != nil {
		return key, nil
	}
	_, err, _ := a.refresh.Do("jwks", func() (any, error) {
		a.mu.Lock()
		// One fixed flight key and a refresh interval bound unknown-kid traffic.
		if time.Now().Before(a.nextRefresh) {
			a.mu.Unlock()
			return nil, auth.ErrInvalidToken
		}
		a.nextRefresh = time.Now().Add(30 * time.Second)
		a.mu.Unlock()
		// A shared refresh must survive the initiating caller disconnecting.
		// The HTTP client still bounds the fetch to ten seconds.
		return nil, a.refreshKeys(context.WithoutCancel(ctx))
	})
	if key := a.cachedKey(kid); key != nil {
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, auth.ErrInvalidToken
}

func (a *WorkOSAuth) cachedKey(kid string) *rsa.PublicKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Now().Before(a.keysExpire) {
		return a.keys[kid]
	}
	return nil
}

func (a *WorkOSAuth) refreshKeys(ctx context.Context) error {
	body, err := a.request(ctx, http.MethodGet, a.issuer+"/oauth2/jwks", "")
	if err != nil {
		return auth.ErrInvalidToken
	}
	var jwks struct {
		Keys []struct {
			Type string `json:"kty"`
			ID   string `json:"kid"`
			Use  string `json:"use"`
			Alg  string `json:"alg"`
			N    string `json:"n"`
			E    string `json:"e"`
		} `json:"keys"`
	}
	if json.Unmarshal(body, &jwks) != nil {
		return auth.ErrInvalidToken
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Type != "RSA" || key.ID == "" || (key.Use != "" && key.Use != "sig") || (key.Alg != "" && key.Alg != "RS256") {
			continue
		}
		n, nErr := base64.RawURLEncoding.Strict().DecodeString(key.N)
		e, eErr := base64.RawURLEncoding.Strict().DecodeString(key.E)
		if nErr != nil || eErr != nil || len(n) < 256 || len(n) > 1024 || len(e) == 0 || len(e) > 4 {
			continue
		}
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e).Int64()
		if modulus.BitLen() < 2048 || exponent < 3 || exponent > 1<<31-1 || exponent%2 == 0 {
			continue
		}
		if keys[key.ID] != nil {
			return auth.ErrInvalidToken
		}
		keys[key.ID] = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	if len(keys) == 0 {
		return auth.ErrInvalidToken
	}
	a.mu.Lock()
	a.keys, a.keysExpire = keys, time.Now().Add(time.Hour)
	a.mu.Unlock()
	return nil
}
