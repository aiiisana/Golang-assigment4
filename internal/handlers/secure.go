package handlers

import (
	"net/http"

	"go.uber.org/zap"
)

func SecureDataHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем информацию о пользователе из контекста (например, из JWT токена)
	user, ok := r.Context().Value("user").(string) // Предположим, что пользователь хранится в контексте
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Логируем информацию о пользователе
	logger, _ := zap.NewProduction()
	logger.Info("User authenticated", zap.String("user", user))

	// Верните защищенные данные
	w.Write([]byte("Secure data for " + user))
}
