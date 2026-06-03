package proxy

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/aegis-ai/aegis/internal/policy"
	"github.com/aegis-ai/aegis/internal/store"
)

// Server is the aegis intercept API.
type Server struct {
	addr      string
	store     *store.Store
	evaluator *policy.Evaluator
	httpSrv   *http.Server
}

// NewServer creates a Server but does not start listening.
// adminKey guards the decision resolve/list endpoints; pass "" to reuse apiKey.
func NewServer(addr, apiKey, adminKey string, cfg *policy.Config, db *store.Store, behindProxy bool) *Server {
	s := &Server{
		addr:      addr,
		store:     db,
		evaluator: policy.NewEvaluator(cfg),
	}

	mux := http.NewServeMux()
	auth := authMiddleware(apiKey, behindProxy)
	if adminKey == "" {
		adminKey = apiKey
	}
	adminAuth := authMiddleware(adminKey, behindProxy)

	mux.Handle("POST /v1/intercept",      auth(http.HandlerFunc(s.handleIntercept)))
	mux.Handle("GET /v1/session/{id}",    auth(http.HandlerFunc(s.handleGetSession)))
	mux.Handle("GET /v1/traces",          auth(http.HandlerFunc(s.handleGetTraces)))

	// DEFER: agents poll their own decision; operators resolve/list (admin-authed).
	mux.Handle("GET /v1/decisions/{id}",          auth(http.HandlerFunc(s.handleGetDecision)))
	mux.Handle("POST /v1/decisions/{id}/resolve", adminAuth(http.HandlerFunc(s.handleResolveDecision)))
	mux.Handle("GET /v1/decisions",               adminAuth(http.HandlerFunc(s.handleListDecisions)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error", "error": "database unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	s.httpSrv = &http.Server{
		Addr:           addr,
		Handler:        loggingMiddleware(requestIDMiddleware(mux)),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64 KB
	}
	return s
}

// Start runs the server until ctx is cancelled, then shuts down gracefully.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}
