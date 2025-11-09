package jwt

import (
	"testing"
	"time"
)

func TestGenerateAccessToken(t *testing.T) {
	config := &Config{
		SecretKey:      "test-secret-key",
		Issuer:         "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
	}
	manager := NewManager(config)

	userID := "user123"
	email := "test@example.com"
	roles := []string{"user", "admin"}
	extra := map[string]interface{}{"tenant_id": "tenant123"}

	token, err := manager.GenerateAccessToken(userID, email, roles, extra)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated token is empty")
	}

	// Validate the token
	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, claims.UserID)
	}

	if claims.Email != email {
		t.Errorf("Expected Email %s, got %s", email, claims.Email)
	}

	if len(claims.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(claims.Roles))
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	config := &Config{
		SecretKey:       "test-secret-key",
		Issuer:          "test-issuer",
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
	manager := NewManager(config)

	userID := "user123"
	token, err := manager.GenerateRefreshToken(userID)
	if err != nil {
		t.Fatalf("Failed to generate refresh token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated refresh token is empty")
	}

	// Validate the token
	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, claims.UserID)
	}
}

func TestValidateExpiredToken(t *testing.T) {
	config := &Config{
		SecretKey:      "test-secret-key",
		Issuer:         "test-issuer",
		AccessTokenTTL: 1 * time.Millisecond,
	}
	manager := NewManager(config)

	token, _ := manager.GenerateAccessToken("user123", "test@example.com", nil, nil)

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err := manager.ValidateToken(token)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got %v", err)
	}
}

func TestValidateInvalidToken(t *testing.T) {
	config := &Config{
		SecretKey: "test-secret-key",
		Issuer:    "test-issuer",
	}
	manager := NewManager(config)

	_, err := manager.ValidateToken("invalid.token.here")
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}
}

func TestRefreshAccessToken(t *testing.T) {
	config := &Config{
		SecretKey:       "test-secret-key",
		Issuer:          "test-issuer",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
	manager := NewManager(config)

	userID := "user123"
	refreshToken, _ := manager.GenerateRefreshToken(userID)

	email := "test@example.com"
	roles := []string{"user"}
	newAccessToken, err := manager.RefreshAccessToken(refreshToken, email, roles, nil)
	if err != nil {
		t.Fatalf("Failed to refresh access token: %v", err)
	}

	if newAccessToken == "" {
		t.Fatal("New access token is empty")
	}

	// Validate new access token
	claims, err := manager.ValidateToken(newAccessToken)
	if err != nil {
		t.Fatalf("Failed to validate new access token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, claims.UserID)
	}

	if claims.Email != email {
		t.Errorf("Expected Email %s, got %s", email, claims.Email)
	}
}
