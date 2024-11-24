package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var totalRequests = expvar.NewInt("total_requests")

func incrementRequestCount() {
	totalRequests.Add(1)
}

var (
	jwtSecret = []byte("secret-key")

	requestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path"},
	)
	duration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

func init() {
	prometheus.MustRegister(requestCount)
	prometheus.MustRegister(duration)
}

type contextKey string

const (
	UsernameContextKey contextKey = "username"
	RoleContextKey     contextKey = "role"
)

type User struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	Role     string `json:"role"`
}

var validate = validator.New()

func GenerateJWT(username, role string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ParseJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

func hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func validateInput(user User) error {
	if err := validate.Struct(user); err != nil {
		return fmt.Errorf("invalid input: %v", err)
	}
	return nil
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims, err := ParseJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		username, usernameOk := claims["username"].(string)
		role, roleOk := claims["role"].(string)

		if !usernameOk || !roleOk {
			http.Error(w, "Invalid token payload", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "username", username)
		ctx = context.WithValue(ctx, "role", role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func secureDataHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "Unauthorized: username not found", http.StatusUnauthorized)
		return
	}

	role, ok := r.Context().Value("role").(string)
	if !ok {
		http.Error(w, "Unauthorized: role not found", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Secure data accessed by user: %s with role: %s\n", username, role)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateInput(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if user.Username == "admin" && hashPassword(user.Password) == hashPassword("password") {
		token, err := GenerateJWT(user.Username, "admin")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"token": "` + token + `"}`))
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		durationInSec := time.Since(start).Seconds()

		logrus.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   http.StatusOK,
			"duration": durationInSec,
		}).Info("Request processed")

		incrementRequestCount()

		requestCount.WithLabelValues(r.Method, r.URL.Path).Inc()
		duration.WithLabelValues(r.Method, r.URL.Path).Observe(durationInSec)
	})
}

func csrfMiddleware(next http.Handler) http.Handler {
	return csrf.Protect([]byte("32-byte-long-secret"), csrf.Secure(true))(next)
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.DebugLevel)

	r := mux.NewRouter()

	r.Use(csrfMiddleware)
	r.Use(securityHeadersMiddleware)

	r.HandleFunc("/login", loginHandler).Methods("POST")

	secure := r.PathPrefix("/secure").Subrouter()
	secure.Use(JWTMiddleware)
	secure.HandleFunc("/data", secureDataHandler).Methods("GET")

	r.Handle("/metrics", promhttp.Handler())
	r.Use(logRequest)

	r.Handle("/debug/vars", expvar.Handler())

	logrus.Info("Server running on https://localhost:8080")
	http.ListenAndServeTLS(":8080", "server.crt", "server.key", r)
}
