package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegis-ai/aegis/internal/policy"
	"github.com/aegis-ai/aegis/internal/testdb"
)

const agentTestKey = "synthetic-agent-credential"
const adminTestKey = "synthetic-operator-credential"

func request(t *testing.T, handler http.Handler, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-Aegis-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestAdministratorCredentialIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, configured, presented string
		status                      int
	}{
		{"missing", "", agentTestKey, http.StatusServiceUnavailable},
		{"equal", agentTestKey, agentTestKey, http.StatusServiceUnavailable},
		{"empty", "", "", http.StatusServiceUnavailable},
		{"agent", adminTestKey, agentTestKey, http.StatusUnauthorized},
		{"anonymous", adminTestKey, "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer("", agentTestKey, tc.configured, &policy.Config{}, nil, false)
			w := request(t, s.httpSrv.Handler, "POST", "/v1/decisions/invalid!/resolve", tc.presented, `{"action":"approve"}`)
			if w.Code != tc.status {
				t.Fatalf("administrator status = %d, want %d; body = %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

func TestDeferredDecisionApproval(t *testing.T) {
	db := testdb.New(t)
	cfg := &policy.Config{Policies: []policy.Policy{{Name: "human", Trigger: policy.Trigger{Tool: []string{"deploy"}}, Decision: "DEFER"}}}
	for _, adminKey := range []string{"", agentTestKey, adminTestKey} {
		t.Run(fmt.Sprintf("admin-%d", len(adminKey)), func(t *testing.T) {
			s := NewServer("", agentTestKey, adminKey, cfg, db.Store, false)
			for _, action := range []string{"approve", "reject"} {
				body := fmt.Sprintf(`{"session_id":"approval-%d-%s","agent_id":"agent","tool":"deploy"}`, len(adminKey), action)
				w := request(t, s.httpSrv.Handler, "POST", "/v1/intercept", agentTestKey, body)
				var deferred interceptResponse
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &deferred) != nil || deferred.Decision != "DEFER" || deferred.DecisionID == "" {
					t.Fatalf("ordinary interception failed: %d %s", w.Code, w.Body.String())
				}
				resolve := "/v1/decisions/" + deferred.DecisionID + "/resolve"
				payload := fmt.Sprintf(`{"action":%q}`, action)
				for _, path := range []string{resolve, "/v1/decisions", "/v1/metrics"} {
					method := "GET"
					if path == resolve {
						method = "POST"
					}
					w = request(t, s.httpSrv.Handler, method, path, agentTestKey, payload)
					want := http.StatusUnauthorized
					if adminKey != adminTestKey {
						want = http.StatusServiceUnavailable
					}
					if w.Code != want {
						t.Fatalf("agent administrator request = %d, want %d", w.Code, want)
					}
				}
				pd, err := db.Store.GetPendingDecision(context.Background(), deferred.DecisionID)
				if err != nil || pd.Status != "pending" {
					t.Fatalf("agent changed decision: %+v, %v", pd, err)
				}
				if adminKey == adminTestKey {
					w = request(t, s.httpSrv.Handler, "POST", resolve, adminTestKey, payload)
					if w.Code != http.StatusOK {
						t.Fatalf("operator resolution failed: %d %s", w.Code, w.Body.String())
					}
					w = request(t, s.httpSrv.Handler, "GET", "/v1/decisions/"+deferred.DecisionID+"?agent_id=agent", agentTestKey, "")
					wantStatus := "approved"
					if action == "reject" {
						wantStatus = "rejected"
					}
					if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &pd) != nil || pd.Status != wantStatus {
						t.Fatalf("agent poll = %s", w.Body.String())
					}
					w = request(t, s.httpSrv.Handler, "POST", resolve, adminTestKey, payload)
					if w.Code != http.StatusConflict {
						t.Fatalf("repeated resolution = %d, want 409", w.Code)
					}
				}
			}
		})
	}
}

func TestConcurrentInterceptPolicies(t *testing.T) {
	threshold := float64(1)
	costThreshold := float64(0.25)
	for _, tc := range []struct {
		name    string
		trigger policy.Trigger
	}{
		{"calls", policy.Trigger{ToolCallCount: &policy.Condition{Gt: &threshold}}},
		{"tokens", policy.Trigger{TokenCount: &policy.Condition{Gt: &threshold}}},
		{"rate", policy.Trigger{ToolCallsPerMinute: &policy.Condition{Gte: &threshold}}},
		{"cost", policy.Trigger{SessionCostUSD: &policy.Condition{Gte: &costThreshold}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testdb.New(t)
			if _, err := db.Store.GetOrCreateSession(context.Background(), "shared", "agent", ""); err != nil {
				t.Fatal(err)
			}
			cfg := &policy.Config{Policies: []policy.Policy{{Name: "limit", Trigger: tc.trigger, Decision: "DENY"}}}
			servers := []*Server{
				NewServer("", agentTestKey, adminTestKey, cfg, db.Store, false),
				NewServer("", agentTestKey, adminTestKey, cfg, db.Connect(t), false),
			}
			release := db.BlockHistory(t)
			const n = 6
			results := make(chan *httptest.ResponseRecorder, n)
			for i := 0; i < n; i++ {
				go func(i int) {
					results <- request(t, servers[i%2].httpSrv.Handler, "POST", "/v1/intercept", agentTestKey, `{"session_id":"shared","agent_id":"agent","tool":"read","token_count":1,"cost_usd":0.25}`)
				}(i)
			}
			release(n)
			allowed := 0
			for i := 0; i < n; i++ {
				select {
				case w := <-results:
					var response interceptResponse
					if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
						t.Fatalf("intercept failed: %d %s", w.Code, w.Body.String())
					}
					if response.Decision == "ALLOW" {
						allowed++
					} else if response.Decision != "DENY" {
						t.Fatalf("unexpected decision %q", response.Decision)
					}
				case <-time.After(15 * time.Second):
					t.Fatal("intercept did not finish")
				}
			}
			if allowed != 1 {
				t.Errorf("overlapping requests allowed = %d, want 1", allowed)
			}
			sess, err := db.Store.GetSession(context.Background(), "shared")
			if err != nil {
				t.Fatal(err)
			}
			if sess.ToolCallCount != n || sess.TokenCount != n || sess.CostUSD != n*0.25 {
				t.Errorf("persisted counters = %+v, want calls=%d tokens=%d cost=1.5", sess, n, n)
			}
			history, err := db.Store.GetToolCallHistory(context.Background(), "shared", 20)
			if err != nil || len(history) != n {
				t.Errorf("persisted history = %d, %v; want %d", len(history), err, n)
			}
		})
	}
}

func TestInterceptPersistenceFailureRollsBack(t *testing.T) {
	for _, tc := range []struct{ name, fault, restore string }{
		{"history", "ALTER TABLE tool_calls RENAME TO unavailable", "ALTER TABLE unavailable RENAME TO tool_calls"},
		{"call", "ALTER TABLE tool_calls ADD CHECK (tool <> 'fail')", ""},
		{"trace", "ALTER TABLE traces ADD CHECK (tool <> 'fail')", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testdb.New(t)
			ctx := context.Background()
			if _, err := db.Store.GetOrCreateSession(ctx, "atomic", "agent", ""); err != nil {
				t.Fatal(err)
			}
			db.Exec(t, tc.fault)
			cfg := &policy.Config{Policies: []policy.Policy{{Name: "approval", Trigger: policy.Trigger{Tool: []string{"fail"}}, Decision: "DEFER"}}}
			s := NewServer("", agentTestKey, adminTestKey, cfg, db.Store, false)
			w := request(t, s.httpSrv.Handler, "POST", "/v1/intercept", agentTestKey, `{"session_id":"atomic","agent_id":"agent","tool":"fail","token_count":5,"cost_usd":0.25}`)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("failed persistence returned %d %s, want 500", w.Code, w.Body.String())
			}
			if tc.restore != "" {
				db.Exec(t, tc.restore)
			}
			sess, err := db.Store.GetSession(ctx, "atomic")
			if err != nil || sess.ToolCallCount != 0 || sess.TokenCount != 0 || sess.CostUSD != 0 {
				t.Fatalf("failed call changed counters: %+v, %v", sess, err)
			}
			history, err := db.Store.GetToolCallHistory(ctx, "atomic", 20)
			if err != nil || len(history) != 0 {
				t.Fatalf("failed call recorded history: %+v, %v", history, err)
			}
			pending, err := db.Store.ListPendingDecisions(ctx, 100)
			if err != nil || len(pending) != 0 {
				t.Fatalf("failed call created approval: %+v, %v", pending, err)
			}
			w = request(t, s.httpSrv.Handler, "POST", "/v1/intercept", agentTestKey, `{"session_id":"atomic","agent_id":"other","tool":"read"}`)
			if w.Code != http.StatusForbidden {
				t.Fatalf("cross-agent interception returned %d, want 403", w.Code)
			}
			w = request(t, s.httpSrv.Handler, "POST", "/v1/intercept", agentTestKey, `{"session_id":"atomic","agent_id":"agent","tool":"read"}`)
			var response interceptResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Decision != "ALLOW" {
				t.Fatalf("recovery failed: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
