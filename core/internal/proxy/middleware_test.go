package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func newAuthRequest(key string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if key != "" {
		r.Header.Set("X-Aegis-Key", key)
	}
	return r
}

func TestAuthMiddlewareAllowsCorrectKey(t *testing.T) {
	mw := authMiddleware("correct-key-for-testing-purposes-1234", false)
	rr := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rr, newAuthRequest("correct-key-for-testing-purposes-1234"))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddlewareRejectsWrongKey(t *testing.T) {
	mw := authMiddleware("correct-key-for-testing-purposes-1234", false)
	rr := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rr, newAuthRequest("wrong-key"))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddlewareRejectsMissingKey(t *testing.T) {
	mw := authMiddleware("correct-key-for-testing-purposes-1234", false)
	rr := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rr, newAuthRequest(""))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddlewareRejectsKeyWithDifferentLength(t *testing.T) {
	// Key with same prefix but different length must still be rejected.
	mw := authMiddleware("correct-key-for-testing-purposes-1234", false)
	rr := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rr, newAuthRequest("correct-key-for-testing-purposes"))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddlewareBlocksAfterTooManyFailures(t *testing.T) {
	mw := authMiddleware("correct-key-for-testing-purposes-1234", false)
	handler := mw(okHandler)
	// exceed the limit (10 failures per minute)
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, newAuthRequest("bad"))
	}
	// 11th attempt should be rate-limited
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, newAuthRequest("bad"))
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after too many failures, got %d", rr.Code)
	}
}

func TestAuthMiddlewareResetsCounterOnSuccess(t *testing.T) {
	key := "correct-key-for-testing-purposes-1234"
	mw := authMiddleware(key, false)
	handler := mw(okHandler)
	// 5 bad attempts
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, newAuthRequest("bad"))
	}
	// correct key clears the counter
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, newAuthRequest(key))
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 after reset, got %d", rr.Code)
	}
	// 5 more bad attempts should still be under the limit
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, newAuthRequest("bad"))
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, newAuthRequest("bad"))
	// only 5 bad attempts since last reset — should still be 401, not 429
	if rr.Code == http.StatusTooManyRequests {
		t.Error("counter was not reset after successful auth")
	}
}

func TestIPLimiterWindowExpiry(t *testing.T) {
	l := newIPLimiter(3, 50*time.Millisecond)
	for i := 0; i < 3; i++ {
		l.record("1.2.3.4")
	}
	if !l.isBlocked("1.2.3.4") {
		t.Error("expected blocked after 3 failures")
	}
	time.Sleep(60 * time.Millisecond)
	if l.isBlocked("1.2.3.4") {
		t.Error("expected unblocked after window expiry")
	}
}
