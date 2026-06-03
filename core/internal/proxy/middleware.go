package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ctxKey string

const reqIDKey ctxKey = "req_id"

// authMiddleware enforces X-Aegis-Key using length-invariant SHA-256 comparison
// and blocks IPs that exceed 10 failed attempts per minute.
func authMiddleware(apiKey string) func(http.Handler) http.Handler {
	hashed := sha256sum(apiKey)
	limiter := newIPLimiter(10, time.Minute)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if limiter.isBlocked(ip) {
				writeError(w, http.StatusTooManyRequests, "too many failed auth attempts")
				return
			}
			provided := r.Header.Get("X-Aegis-Key")
			if subtle.ConstantTimeCompare(sha256sum(provided), hashed) != 1 {
				limiter.record(ip)
				slog.Warn("auth failure", "ip", ip)
				writeError(w, http.StatusUnauthorized, "invalid or missing api key")
				return
			}
			limiter.reset(ip)
			next.ServeHTTP(w, r)
		})
	}
}

// sha256sum returns the SHA-256 digest of s as a byte slice.
// Hashing before ConstantTimeCompare prevents length-based side-channel leakage.
func sha256sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// clientIP extracts the originating client IP from X-Forwarded-For or RemoteAddr.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if idx := strings.Index(fwd, ","); idx != -1 {
			return strings.TrimSpace(fwd[:idx])
		}
		return strings.TrimSpace(fwd)
	}
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// ipLimiter tracks failed auth attempts per IP within a rolling window.
type ipLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipEntry
	max     int
	window  time.Duration
}

type ipEntry struct {
	count     int
	windowEnd time.Time
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{
		entries: make(map[string]*ipEntry),
		max:     max,
		window:  window,
	}
}

func (l *ipLimiter) record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok || time.Now().After(e.windowEnd) {
		l.entries[ip] = &ipEntry{count: 1, windowEnd: time.Now().Add(l.window)}
		return
	}
	e.count++
}

func (l *ipLimiter) isBlocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		return false
	}
	if time.Now().After(e.windowEnd) {
		delete(l.entries, ip)
		return false
	}
	return e.count >= l.max
}

func (l *ipLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// requestIDMiddleware attaches a UUID to every request and response.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		ctx := context.WithValue(r.Context(), reqIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggingMiddleware logs method, path, status, and latency for every request.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &wrappedWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"latency_ms", time.Since(start).Milliseconds(),
			"req_id", r.Context().Value(reqIDKey),
		)
	})
}

type wrappedWriter struct {
	http.ResponseWriter
	status int
}

func (w *wrappedWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
