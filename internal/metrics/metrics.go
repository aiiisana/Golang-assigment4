package middleware

// import (
// 	"net/http"
// 	"strings"

// 	"lab4/internal/auth"
// )

// // AuthMiddleware is the middleware that checks for a valid JWT token
// func AuthMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// Get the JWT token from the Authorization header
// 		token := r.Header.Get("Authorization")
// 		if token == "" {
// 			http.Error(w, "Forbidden", http.StatusForbidden)
// 			return
// 		}

// 		// Remove "Bearer " prefix
// 		token = strings.TrimPrefix(token, "Bearer ")

// 		// Validate the token and get the claims
// 		claims, err := auth.ValidateToken(token)
// 		if err != nil {
// 			http.Error(w, "Forbidden", http.StatusForbidden)
// 			return
// 		}

// 		// Optionally set user information in context (for use in handlers)
// 		r.Header.Set("Username", claims.Username)
// 		r.Header.Set("Role", claims.Role)

// 		// Proceed with the next handler
// 		next.ServeHTTP(w, r)
// 	})
// }
