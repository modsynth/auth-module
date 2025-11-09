package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/modsynth/auth-module/jwt"
	"github.com/modsynth/auth-module/middleware"
	"github.com/modsynth/auth-module/oauth"
)

func main() {
	// Initialize JWT Manager
	jwtConfig := &jwt.Config{
		SecretKey:       "your-secret-key-change-in-production",
		Issuer:          "modsynth-auth-example",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
	jwtManager := jwt.NewManager(jwtConfig)

	// Initialize OAuth Manager
	oauthManager := oauth.NewManager()
	oauthManager.RegisterProvider(&oauth.Provider{
		Name:         "google",
		ClientID:     "your-google-client-id",
		ClientSecret: "your-google-client-secret",
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     oauth.GoogleEndpoint,
	})

	// Initialize Auth Middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtManager)

	// Routes
	http.HandleFunc("/login", handleLogin(jwtManager))
	http.HandleFunc("/refresh", handleRefresh(jwtManager))
	http.HandleFunc("/auth/google", handleOAuthLogin(oauthManager))
	http.HandleFunc("/auth/google/callback", handleOAuthCallback(oauthManager, jwtManager))

	// Protected routes
	http.Handle("/protected", authMiddleware.Authenticate(http.HandlerFunc(handleProtected)))
	http.Handle("/admin", authMiddleware.Authenticate(
		authMiddleware.RequireRole("admin")(http.HandlerFunc(handleAdmin)),
	))

	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleLogin(jwtManager *jwt.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In production, validate credentials against database
		userID := "user123"
		email := "user@example.com"
		roles := []string{"user"}

		accessToken, err := jwtManager.GenerateAccessToken(userID, email, roles, nil)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		refreshToken, err := jwtManager.GenerateRefreshToken(userID)
		if err != nil {
			http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s","refresh_token":"%s"}`, accessToken, refreshToken)
	}
}

func handleRefresh(jwtManager *jwt.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshToken := r.Header.Get("X-Refresh-Token")
		if refreshToken == "" {
			http.Error(w, "No refresh token provided", http.StatusBadRequest)
			return
		}

		// In production, fetch user data from database
		email := "user@example.com"
		roles := []string{"user"}

		accessToken, err := jwtManager.RefreshAccessToken(refreshToken, email, roles, nil)
		if err != nil {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s"}`, accessToken)
	}
}

func handleOAuthLogin(oauthManager *oauth.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := oauth.GenerateState()
		if err != nil {
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}

		// In production, store state in session/cache for validation
		authURL, err := oauthManager.GetAuthURL("google", state)
		if err != nil {
			http.Error(w, "Failed to get auth URL", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}

func handleOAuthCallback(oauthManager *oauth.Manager, jwtManager *jwt.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		_ = r.URL.Query().Get("state") // In production, validate state against stored value

		token, err := oauthManager.ExchangeCode(r.Context(), "google", code)
		if err != nil {
			http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
			return
		}

		// In production, use token to fetch user info and create/update user in database
		// For this example, we'll create a JWT token
		userID := "oauth-user-123"
		email := "oauth@example.com"
		roles := []string{"user"}

		accessToken, err := jwtManager.GenerateAccessToken(userID, email, roles, nil)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s","oauth_token":"%s"}`, accessToken, token.AccessToken)
	}
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetUserIDFromContext(r.Context())
	claims, _ := middleware.GetClaimsFromContext(r.Context())

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"Protected resource","user_id":"%s","email":"%s"}`, userID, claims.Email)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.GetUserIDFromContext(r.Context())

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message":"Admin resource","user_id":"%s"}`, userID)
}
