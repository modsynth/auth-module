package oauth

import (
	"context"
	"testing"

	"golang.org/x/oauth2"
)

func TestRegisterProvider(t *testing.T) {
	manager := NewManager()

	provider := &Provider{
		Name:         "google",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     GoogleEndpoint,
	}

	manager.RegisterProvider(provider)

	if _, exists := manager.providers["google"]; !exists {
		t.Error("Provider was not registered")
	}
}

func TestGetAuthURL(t *testing.T) {
	manager := NewManager()

	provider := &Provider{
		Name:         "google",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     GoogleEndpoint,
	}

	manager.RegisterProvider(provider)

	state := "random-state-string"
	authURL, err := manager.GetAuthURL("google", state)
	if err != nil {
		t.Fatalf("Failed to get auth URL: %v", err)
	}

	if authURL == "" {
		t.Error("Auth URL is empty")
	}

	// Check if URL contains essential components
	if len(authURL) < 50 {
		t.Error("Auth URL seems too short")
	}
}

func TestGetAuthURLInvalidProvider(t *testing.T) {
	manager := NewManager()

	_, err := manager.GetAuthURL("nonexistent", "state")
	if err == nil {
		t.Error("Expected error for nonexistent provider, got nil")
	}
}

func TestExchangeCodeInvalidProvider(t *testing.T) {
	manager := NewManager()
	ctx := context.Background()

	_, err := manager.ExchangeCode(ctx, "nonexistent", "code")
	if err == nil {
		t.Error("Expected error for nonexistent provider, got nil")
	}
}

func TestExchangeCodeEmptyCode(t *testing.T) {
	manager := NewManager()
	ctx := context.Background()

	provider := &Provider{
		Name:         "google",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     GoogleEndpoint,
	}

	manager.RegisterProvider(provider)

	_, err := manager.ExchangeCode(ctx, "google", "")
	if err != ErrNoAuthCode {
		t.Errorf("Expected ErrNoAuthCode, got %v", err)
	}
}

func TestGenerateState(t *testing.T) {
	state1, err := GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate state: %v", err)
	}

	if state1 == "" {
		t.Error("Generated state is empty")
	}

	state2, err := GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate second state: %v", err)
	}

	if state1 == state2 {
		t.Error("Generated states are identical (should be random)")
	}

	// State should be base64 URL encoded (at least 40 characters for 32 bytes)
	if len(state1) < 40 {
		t.Error("Generated state is too short")
	}
}

func TestGetClient(t *testing.T) {
	manager := NewManager()
	ctx := context.Background()

	provider := &Provider{
		Name:         "google",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     GoogleEndpoint,
	}

	manager.RegisterProvider(provider)

	token := &oauth2.Token{
		AccessToken: "test-access-token",
	}

	config, err := manager.GetClient(ctx, "google", token)
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	if config == nil {
		t.Error("Client config is nil")
	}
}

func TestEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		endpoint oauth2.Endpoint
	}{
		{"Google", GoogleEndpoint},
		{"GitHub", GitHubEndpoint},
		{"Facebook", FacebookEndpoint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.endpoint.AuthURL == "" {
				t.Errorf("%s AuthURL is empty", tt.name)
			}
			if tt.endpoint.TokenURL == "" {
				t.Errorf("%s TokenURL is empty", tt.name)
			}
		})
	}
}
