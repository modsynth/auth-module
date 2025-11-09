package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidToken is returned when the token is invalid
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken is returned when the token has expired
	ErrExpiredToken = errors.New("token has expired")
	// ErrInvalidSigningMethod is returned when the signing method is invalid
	ErrInvalidSigningMethod = errors.New("invalid signing method")
)

// Claims represents the JWT claims structure
type Claims struct {
	UserID string                 `json:"user_id"`
	Email  string                 `json:"email"`
	Roles  []string               `json:"roles,omitempty"`
	Extra  map[string]interface{} `json:"extra,omitempty"`
	jwt.RegisteredClaims
}

// Config holds the JWT configuration
type Config struct {
	SecretKey       string
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// Manager handles JWT token operations
type Manager struct {
	config *Config
}

// NewManager creates a new JWT manager
func NewManager(config *Config) *Manager {
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 15 * time.Minute
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	return &Manager{config: config}
}

// GenerateAccessToken generates a new access token
func (m *Manager) GenerateAccessToken(userID, email string, roles []string, extra map[string]interface{}) (string, error) {
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		Extra:  extra,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.config.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    m.config.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.config.SecretKey))
}

// GenerateRefreshToken generates a new refresh token
func (m *Manager) GenerateRefreshToken(userID string) (string, error) {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.config.RefreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    m.config.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.config.SecretKey))
}

// ValidateToken validates a JWT token and returns the claims
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(m.config.SecretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// RefreshAccessToken generates a new access token from a refresh token
func (m *Manager) RefreshAccessToken(refreshTokenString string, email string, roles []string, extra map[string]interface{}) (string, error) {
	claims, err := m.ValidateToken(refreshTokenString)
	if err != nil {
		return "", err
	}

	return m.GenerateAccessToken(claims.UserID, email, roles, extra)
}
