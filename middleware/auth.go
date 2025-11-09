package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/modsynth/auth-module/jwt"
)

// ContextKey is the type for context keys
type ContextKey string

const (
	// ClaimsContextKey is the key for storing claims in context
	ClaimsContextKey ContextKey = "claims"
	// UserIDContextKey is the key for storing user ID in context
	UserIDContextKey ContextKey = "user_id"
)

var (
	// ErrNoAuthHeader is returned when no authorization header is present
	ErrNoAuthHeader = errors.New("no authorization header")
	// ErrInvalidAuthHeader is returned when the authorization header is malformed
	ErrInvalidAuthHeader = errors.New("invalid authorization header format")
)

// AuthMiddleware provides HTTP middleware for JWT authentication
type AuthMiddleware struct {
	jwtManager *jwt.Manager
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(jwtManager *jwt.Manager) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager: jwtManager,
	}
}

// Authenticate is the middleware function for HTTP authentication
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := m.jwtManager.ValidateToken(token)
		if err != nil {
			if errors.Is(err, jwt.ErrExpiredToken) {
				http.Error(w, "token expired", http.StatusUnauthorized)
				return
			}
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		ctx = context.WithValue(ctx, UserIDContextKey, claims.UserID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole checks if the user has the required role
func (m *AuthMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsContextKey).(*jwt.Claims)
			if !ok {
				http.Error(w, "no claims in context", http.StatusUnauthorized)
				return
			}

			hasRole := false
			for _, r := range claims.Roles {
				if r == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole checks if the user has any of the required roles
func (m *AuthMiddleware) RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsContextKey).(*jwt.Claims)
			if !ok {
				http.Error(w, "no claims in context", http.StatusUnauthorized)
				return
			}

			hasRole := false
			for _, requiredRole := range roles {
				for _, userRole := range claims.Roles {
					if userRole == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractToken extracts the JWT token from the Authorization header
func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

// GetClaimsFromContext retrieves claims from the request context
func GetClaimsFromContext(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*jwt.Claims)
	return claims, ok
}

// GetUserIDFromContext retrieves user ID from the request context
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDContextKey).(string)
	return userID, ok
}
