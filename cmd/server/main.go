package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"pawsy/internal/auth/app"
	"pawsy/internal/auth/app/security"
	"pawsy/internal/auth/cache"
	"pawsy/internal/auth/repo/postgres"
	"pawsy/internal/auth/transport/rest"
	"pawsy/pkg/config"
	mylogger "pawsy/pkg/logger"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if err := runAuth(ctx, cfg); err != nil {
		log.Fatalf("application error: %v", err)
	}
}

func runAuth(ctx context.Context, cfg *config.Config) error {
	logger := mylogger.New(cfg.Logger, "auth")

	userCache := cache.NewUserRepo()

	dbPool, err := postgres.NewPool(ctx, cfg.Auth.DB)
	if err != nil {
		return fmt.Errorf("db connection: %w", err)
	}
	defer dbPool.Close()

	userRepo := postgres.NewUserRepo(dbPool)
	refreshRepo := postgres.NewRefreshTokenRepo(dbPool)

	tokenManager := security.NewJWTManager(cfg.Auth.JWT)
	passwordHasher := security.NewArgon2Hasher(cfg.Auth.Argon2)
	tokenHasher := security.NewTokenHasher(cfg.Auth.SHA256)

	authService := app.NewAuthService(
		userRepo,
		userCache,
		refreshRepo,
		passwordHasher,
		tokenHasher,
		tokenManager,
		logger,
	)

	authHandler := rest.NewAuthHandler(authService, cfg.Auth.Handler.RefreshTTLDays, cfg.Auth.Handler.TimeContextInSecond, logger)

	router := setupRouter(authHandler, logger)

	srv := &http.Server{
		Addr:         ":" + cfg.Auth.AuthServer.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("server started", "port", cfg.Auth.AuthServer.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	logger.Info("server stopped")
	return nil
}

func setupRouter(handler *rest.AuthHandler, logger *slog.Logger) *mux.Router {
	r := mux.NewRouter()
	r.Use(rest.LoggingMiddleware(logger))

	r.Path("/login").Methods("POST").HandlerFunc(handler.HandleLogin)
	r.Path("/register").Methods("POST").HandlerFunc(handler.HandleRegister)
	r.Path("/refresh").Methods("POST").HandlerFunc(handler.HandleRefresh)
	r.Path("/logout").Methods("POST").HandlerFunc(handler.HandleLogout)
	r.Path("/logout/all").Methods("POST").HandlerFunc(handler.HandleLogoutAll)

	return r
}
