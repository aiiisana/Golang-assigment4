package handlers

import (
	"encoding/json"
	"net/http"

	"lab4/internal/auth" // импортируйте пакет auth, где ваша логика с JWT
)

// LoginHandler - обработчик для маршрута /login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Чтение данных из тела запроса
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Проверка логина и пароля
	if loginData.Username == "admin" && loginData.Password == "password" {
		// Генерация токена JWT
		token, err := auth.GenerateJWT(loginData.Username)
		if err != nil {
			http.Error(w, "Could not generate token", http.StatusInternalServerError)
			return
		}

		// Отправка токена в ответе
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": token,
		})
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}
