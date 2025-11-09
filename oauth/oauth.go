package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
)

var (
	// ErrInvalidState is returned when the OAuth state is invalid
	ErrInvalidState = errors.New("invalid oauth state")
	// ErrNoAuthCode is returned when no authorization code is provided
	ErrNoAuthCode = errors.New("no authorization code provided")
)

// Provider represents an OAuth2 provider configuration
type Provider struct {
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Endpoint     oauth2.Endpoint
}

// Manager handles OAuth2 operations
type Manager struct {
	providers map[string]*oauth2.Config
}

// NewManager creates a new OAuth2 manager
func NewManager() *Manager {
	return &Manager{
		providers: make(map[string]*oauth2.Config),
	}
}

// RegisterProvider registers an OAuth2 provider
func (m *Manager) RegisterProvider(provider *Provider) {
	config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  provider.RedirectURL,
		Scopes:       provider.Scopes,
		Endpoint:     provider.Endpoint,
	}
	m.providers[provider.Name] = config
}

// GetAuthURL generates an OAuth2 authorization URL
func (m *Manager) GetAuthURL(providerName string, state string) (string, error) {
	config, exists := m.providers[providerName]
	if !exists {
		return "", fmt.Errorf("provider %s not found", providerName)
	}

	return config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// ExchangeCode exchanges an authorization code for a token
func (m *Manager) ExchangeCode(ctx context.Context, providerName string, code string) (*oauth2.Token, error) {
	config, exists := m.providers[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	if code == "" {
		return nil, ErrNoAuthCode
	}

	return config.Exchange(ctx, code)
}

// RefreshToken refreshes an OAuth2 token
func (m *Manager) RefreshToken(ctx context.Context, providerName string, refreshToken string) (*oauth2.Token, error) {
	config, exists := m.providers[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	tokenSource := config.TokenSource(ctx, token)
	return tokenSource.Token()
}

// GetClient returns an HTTP client configured with the OAuth2 token
func (m *Manager) GetClient(ctx context.Context, providerName string, token *oauth2.Token) (*oauth2.Config, error) {
	config, exists := m.providers[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	return config, nil
}

// GenerateState generates a random state string for OAuth2 flow
func GenerateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Common OAuth2 provider endpoints
var (
	// GoogleEndpoint is the OAuth2 endpoint for Google
	GoogleEndpoint = oauth2.Endpoint{
		AuthURL:  "https://accounts.google.com/o/oauth2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
	}

	// GitHubEndpoint is the OAuth2 endpoint for GitHub
	GitHubEndpoint = oauth2.Endpoint{
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	}

	// FacebookEndpoint is the OAuth2 endpoint for Facebook
	FacebookEndpoint = oauth2.Endpoint{
		AuthURL:  "https://www.facebook.com/v12.0/dialog/oauth",
		TokenURL: "https://graph.facebook.com/v12.0/oauth/access_token",
	}
)
