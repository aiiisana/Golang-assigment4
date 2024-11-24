package security

import (
	"net/http"

	"github.com/gorilla/csrf"
	"golang.org/x/crypto/bcrypt"
)

// Хэширование пароля
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Проверка пароля
func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// CSRF защита
func CSRFProtection() func(http.Handler) http.Handler {
	return csrf.Protect([]byte("32-byte-long-secret-key"))
}
