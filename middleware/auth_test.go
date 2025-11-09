package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modsynth/auth-module/jwt"
)

func TestAuthMiddleware_Authenticate(t *testing.T) {
	config := &jwt.Config{
		SecretKey:      "test-secret",
		Issuer:         "test",
		AccessTokenTTL: 15 * time.Minute,
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	token, _ := jwtManager.GenerateAccessToken("user123", "test@example.com", []string{"user"}, nil)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetClaimsFromContext(r.Context())
		if !ok {
			t.Error("Claims not found in context")
		}
		if claims.UserID != "user123" {
			t.Errorf("Expected user ID user123, got %s", claims.UserID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_NoAuthHeader(t *testing.T) {
	config := &jwt.Config{
		SecretKey: "test-secret",
		Issuer:    "test",
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	config := &jwt.Config{
		SecretKey: "test-secret",
		Issuer:    "test",
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	config := &jwt.Config{
		SecretKey:      "test-secret",
		Issuer:         "test",
		AccessTokenTTL: 1 * time.Millisecond,
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	token, _ := jwtManager.GenerateAccessToken("user123", "test@example.com", []string{"user"}, nil)
	time.Sleep(10 * time.Millisecond)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_RequireRole(t *testing.T) {
	config := &jwt.Config{
		SecretKey:      "test-secret",
		Issuer:         "test",
		AccessTokenTTL: 15 * time.Minute,
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	token, _ := jwtManager.GenerateAccessToken("user123", "test@example.com", []string{"admin"}, nil)

	handler := middleware.Authenticate(
		middleware.RequireRole("admin")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_RequireRole_Forbidden(t *testing.T) {
	config := &jwt.Config{
		SecretKey:      "test-secret",
		Issuer:         "test",
		AccessTokenTTL: 15 * time.Minute,
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	token, _ := jwtManager.GenerateAccessToken("user123", "test@example.com", []string{"user"}, nil)

	handler := middleware.Authenticate(
		middleware.RequireRole("admin")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", rec.Code)
	}
}

func TestAuthMiddleware_RequireAnyRole(t *testing.T) {
	config := &jwt.Config{
		SecretKey:      "test-secret",
		Issuer:         "test",
		AccessTokenTTL: 15 * time.Minute,
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	token, _ := jwtManager.GenerateAccessToken("user123", "test@example.com", []string{"moderator"}, nil)

	handler := middleware.Authenticate(
		middleware.RequireAnyRole("admin", "moderator")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestExtractToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	token, err := extractToken(req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if token != "test-token" {
		t.Errorf("Expected token 'test-token', got %s", token)
	}
}

func TestExtractToken_InvalidFormat(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat")

	_, err := extractToken(req)
	if err != ErrInvalidAuthHeader {
		t.Errorf("Expected ErrInvalidAuthHeader, got %v", err)
	}
}

func TestGetUserIDFromContext(t *testing.T) {
	config := &jwt.Config{
		SecretKey:      "test-secret",
		Issuer:         "test",
		AccessTokenTTL: 15 * time.Minute,
	}
	jwtManager := jwt.NewManager(config)
	middleware := NewAuthMiddleware(jwtManager)

	token, _ := jwtManager.GenerateAccessToken("user123", "test@example.com", []string{"user"}, nil)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserIDFromContext(r.Context())
		if !ok {
			t.Error("User ID not found in context")
		}
		if userID != "user123" {
			t.Errorf("Expected user ID user123, got %s", userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}
