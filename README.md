# Auth Module

> JWT + OAuth2.0 authentication module for Go

Part of the [Modsynth](https://github.com/modsynth) ecosystem.

## Features

- **JWT Token Management**
  - Access token generation and validation
  - Refresh token support
  - Custom claims (user ID, email, roles, extra data)
  - Configurable token expiration
  - HMAC-SHA256 signing

- **OAuth2.0 Authentication**
  - Multiple provider support (Google, GitHub, Facebook)
  - Authorization URL generation
  - Code exchange
  - Token refresh
  - Secure state generation

- **HTTP Middleware**
  - JWT authentication middleware
  - Role-based access control (RBAC)
  - Context-based user information
  - Bearer token extraction

## Installation

```bash
go get github.com/modsynth/auth-module
```

## Quick Start

### JWT Authentication

```go
package main

import (
    "time"
    "github.com/modsynth/auth-module/jwt"
)

func main() {
    // Configure JWT manager
    config := &jwt.Config{
        SecretKey:       "your-secret-key",
        Issuer:          "your-app",
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
    }
    manager := jwt.NewManager(config)

    // Generate access token
    token, err := manager.GenerateAccessToken(
        "user123",
        "user@example.com",
        []string{"user", "admin"},
        map[string]interface{}{"tenant_id": "tenant123"},
    )

    // Validate token
    claims, err := manager.ValidateToken(token)

    // Generate refresh token
    refreshToken, err := manager.GenerateRefreshToken("user123")
}
```

### OAuth2.0 Authentication

```go
package main

import (
    "github.com/modsynth/auth-module/oauth"
)

func main() {
    // Initialize OAuth manager
    manager := oauth.NewManager()

    // Register Google provider
    manager.RegisterProvider(&oauth.Provider{
        Name:         "google",
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURL:  "http://localhost:8080/callback",
        Scopes:       []string{"email", "profile"},
        Endpoint:     oauth.GoogleEndpoint,
    })

    // Generate auth URL
    state, _ := oauth.GenerateState()
    authURL, _ := manager.GetAuthURL("google", state)

    // Exchange code for token
    token, _ := manager.ExchangeCode(ctx, "google", code)
}
```

### HTTP Middleware

```go
package main

import (
    "net/http"
    "github.com/modsynth/auth-module/jwt"
    "github.com/modsynth/auth-module/middleware"
)

func main() {
    // Setup
    jwtManager := jwt.NewManager(config)
    authMiddleware := middleware.NewAuthMiddleware(jwtManager)

    // Protected route
    http.Handle("/protected",
        authMiddleware.Authenticate(http.HandlerFunc(handler)))

    // Admin-only route
    http.Handle("/admin",
        authMiddleware.Authenticate(
            authMiddleware.RequireRole("admin")(http.HandlerFunc(handler)),
        ))

    // Multiple roles
    http.Handle("/moderator",
        authMiddleware.Authenticate(
            authMiddleware.RequireAnyRole("admin", "moderator")(http.HandlerFunc(handler)),
        ))
}

func handler(w http.ResponseWriter, r *http.Request) {
    // Get user information from context
    userID, _ := middleware.GetUserIDFromContext(r.Context())
    claims, _ := middleware.GetClaimsFromContext(r.Context())
}
```

## Configuration

### JWT Config

```go
type Config struct {
    SecretKey       string        // Secret key for signing tokens (required)
    Issuer          string        // Token issuer identifier
    AccessTokenTTL  time.Duration // Access token lifetime (default: 15 minutes)
    RefreshTokenTTL time.Duration // Refresh token lifetime (default: 7 days)
}
```

### OAuth Provider

```go
type Provider struct {
    Name         string          // Provider name (e.g., "google")
    ClientID     string          // OAuth client ID
    ClientSecret string          // OAuth client secret
    RedirectURL  string          // OAuth redirect URL
    Scopes       []string        // OAuth scopes
    Endpoint     oauth2.Endpoint // OAuth endpoints
}
```

## JWT Claims Structure

```go
type Claims struct {
    UserID string                 `json:"user_id"`
    Email  string                 `json:"email"`
    Roles  []string               `json:"roles,omitempty"`
    Extra  map[string]interface{} `json:"extra,omitempty"`
    jwt.RegisteredClaims
}
```

## Supported OAuth Providers

Built-in endpoint configurations:

- **Google** - `oauth.GoogleEndpoint`
- **GitHub** - `oauth.GitHubEndpoint`
- **Facebook** - `oauth.FacebookEndpoint`

Custom providers can be added by providing an `oauth2.Endpoint`.

## Error Handling

```go
import "github.com/modsynth/auth-module/jwt"

// JWT errors
jwt.ErrInvalidToken         // Token is invalid
jwt.ErrExpiredToken         // Token has expired
jwt.ErrInvalidSigningMethod // Invalid signing method

// OAuth errors
oauth.ErrInvalidState       // OAuth state mismatch
oauth.ErrNoAuthCode        // No authorization code

// Middleware errors
middleware.ErrNoAuthHeader      // Missing Authorization header
middleware.ErrInvalidAuthHeader // Malformed Authorization header
```

## Complete Example

See [examples/main.go](examples/main.go) for a complete HTTP server example with:
- Login endpoint
- Token refresh
- OAuth2.0 login flow
- Protected routes
- Role-based access control

Run the example:

```bash
cd examples
go run main.go
```

Test endpoints:

```bash
# Login
curl http://localhost:8080/login

# Access protected route
curl -H "Authorization: Bearer <token>" http://localhost:8080/protected

# Refresh token
curl -H "X-Refresh-Token: <refresh-token>" http://localhost:8080/refresh

# OAuth login (redirects to Google)
curl http://localhost:8080/auth/google
```

## Testing

Run tests:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

## Security Considerations

1. **Secret Key**: Use a strong, randomly generated secret key in production
2. **HTTPS**: Always use HTTPS in production for token transmission
3. **Token Storage**: Store tokens securely (httpOnly cookies, secure storage)
4. **State Validation**: Validate OAuth state parameter to prevent CSRF
5. **Token Expiration**: Use short-lived access tokens (15 minutes)
6. **Refresh Tokens**: Store refresh tokens securely and implement rotation
7. **Rate Limiting**: Implement rate limiting on authentication endpoints

## Dependencies

- `github.com/golang-jwt/jwt/v5` - JWT implementation
- `golang.org/x/oauth2` - OAuth2 client

## Version

Current version: `v0.1.0`

## License

MIT

## Contributing

Issues and pull requests are welcome at [github.com/modsynth/auth-module](https://github.com/modsynth/auth-module)

## Related Modules

- [cache-module](https://github.com/modsynth/cache-module) - Redis cache for session management
- [db-module](https://github.com/modsynth/db-module) - Database abstraction for user storage
- [api-gateway](https://github.com/modsynth/api-gateway) - API Gateway integration

## Documentation

- [GoDoc](https://pkg.go.dev/github.com/modsynth/auth-module)
- [Modsynth Documentation](https://github.com/modsynth/docs-dev)
