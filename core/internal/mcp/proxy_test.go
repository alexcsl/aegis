package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aegis-ai/aegis/internal/policy"
	"github.com/aegis-ai/aegis/internal/testdb"
)

func TestConcurrentToolCalls(t *testing.T) {
	db := testdb.New(t)
	if _, err := db.Store.GetOrCreateSession(context.Background(), "shared", "agent", ""); err != nil {
		t.Fatal(err)
	}
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(upstream.Close)
	threshold := float64(1)
	cfg := &policy.Config{Policies: []policy.Policy{{Name: "limit", Trigger: policy.Trigger{ToolCallCount: &policy.Condition{Gt: &threshold}}, Decision: "DENY"}}}
	handlers := make([]http.Handler, 2)
	for i := range handlers {
		p, err := NewProxy(upstream.URL, "synthetic-agent", db.Connect(t), cfg)
		if err != nil {
			t.Fatal(err)
		}
		handlers[i] = p.Handler()
	}
	release := db.BlockHistory(t)
	const n = 6
	results := make(chan *httptest.ResponseRecorder, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}`))
			r.Header.Set("X-Aegis-Key", "synthetic-agent")
			r.Header.Set("X-Session-ID", "shared")
			r.Header.Set("X-Agent-ID", "agent")
			w := httptest.NewRecorder()
			handlers[i%2].ServeHTTP(w, r)
			results <- w
		}(i)
	}
	release(n)
	allowed := 0
	for i := 0; i < n; i++ {
		select {
		case w := <-results:
			var body struct {
				Error  *rpcError       `json:"error"`
				Result json.RawMessage `json:"result"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
				t.Fatalf("invalid RPC response: %d %s", w.Code, w.Body.String())
			}
			if body.Error == nil && body.Result != nil {
				allowed++
			} else if body.Error == nil || !strings.Contains(body.Error.Message, "denied by policy") {
				t.Fatalf("unexpected RPC error: %s", w.Body.String())
			}
		case <-time.After(15 * time.Second):
			t.Fatal("RPC did not finish")
		}
	}
	if allowed != 1 || forwarded.Load() != 1 {
		t.Errorf("overlapping calls allowed=%d forwarded=%d, want 1 each", allowed, forwarded.Load())
	}
	sess, err := db.Store.GetSession(context.Background(), "shared")
	if err != nil || sess.ToolCallCount != n {
		t.Errorf("persisted session = %+v, %v; want calls=%d", sess, err, n)
	}
	history, err := db.Store.GetToolCallHistory(context.Background(), "shared", 20)
	if err != nil || len(history) != n {
		t.Errorf("persisted history = %d, %v; want %d", len(history), err, n)
	}
}

func TestPersistenceFailureDoesNotForward(t *testing.T) {
	db := testdb.New(t)
	db.Exec(t, "ALTER TABLE tool_calls ADD CHECK (tool <> 'fail')")
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(upstream.Close)
	p, err := NewProxy(upstream.URL, "synthetic-agent", db.Store, &policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fail"}}`))
	r.Header.Set("X-Aegis-Key", "synthetic-agent")
	r.Header.Set("X-Session-ID", "atomic")
	r.Header.Set("X-Agent-ID", "agent")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	var body struct {
		Error *rpcError `json:"error"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error == nil || !strings.Contains(body.Error.Message, "could not record policy state") {
		t.Fatalf("persistence failure response = %s", w.Body.String())
	}
	if forwarded.Load() != 0 {
		t.Fatalf("forwarded %d calls after persistence failure", forwarded.Load())
	}
	sess, err := db.Store.GetSession(context.Background(), "atomic")
	if err != nil || sess != nil {
		t.Fatalf("failed request committed a session: %+v, %v", sess, err)
	}
}
