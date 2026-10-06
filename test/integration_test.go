package test_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/alert"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/engine"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/rules"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/server"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/testkit"
)

func setup(t *testing.T) (http.Handler, *rules.Store, *engine.Engine) {
	t.Helper()
	now := testkit.Base
	store := rules.NewStore()
	if err := store.Publish(testkit.RuleSetV1("v1")); err != nil {
		t.Fatal(err)
	}
	eng := engine.New(store, alert.NewService(testkit.FixedClock(now)), engine.DefaultConfig(),
		testkit.FixedClock(now))
	return server.New(eng, store).Mux, store, eng
}

func postJSON(t *testing.T, h http.Handler, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// 业务域：端到端 —— 并发接入 -> 判定 -> 唯一告警 -> 并发处置，全链路可追溯。
func TestEndToEnd(t *testing.T) {
	h, _, eng := setup(t)
	now := testkit.Base

	t.Run("健康检查", func(t *testing.T) {
		testkit.Case(t, "端到端HTTP", "服务存活探针")
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("健康检查失败: %d", rec.Code)
		}
	})

	t.Run("并发上报同一大额事件：仅1条决策1条告警", func(t *testing.T) {
		testkit.Case(t, "端到端HTTP", "并发事件去重与唯一告警")
		ev := testkit.Event("evt-1", "ACCT-E2E", 60000, now)
		const n = 30
		var wg sync.WaitGroup
		status200, statusDup := 0, 0
		var mu sync.Mutex
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				b, _ := json.Marshal(ev)
				req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(b))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				var out map[string]any
				_ = json.Unmarshal(rec.Body.Bytes(), &out)
				mu.Lock()
				if out["Status"] == "ACCEPTED" {
					status200++
				}
				if out["Status"] == "DUPLICATE" {
					statusDup++
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		if status200 != 1 || statusDup != n-1 {
			t.Fatalf("期望1接受%d重复，实际 %d/%d", n-1, status200, statusDup)
		}
		alerts := eng.Alerts().ListByEvent("evt-1")
		if len(alerts) != 1 {
			t.Fatalf("同一事件同一规则只能有一条告警，实际 %d", len(alerts))
		}
	})

	t.Run("畸形事件返回422与原因码，且可在拒绝列表查询", func(t *testing.T) {
		testkit.Case(t, "端到端HTTP", "畸形事件422与拒绝可查询")
		bad := testkit.Event("evt-bad", "ACCT-E2E", -1, now)
		b, _ := json.Marshal(bad)
		req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("畸形事件应422，实际 %d", rec.Code)
		}
		if len(eng.Rejections()) != 1 || eng.Rejections()[0].Code != model.RejectAmountInvalid {
			t.Fatalf("拒绝记录缺失或原因不符")
		}
	})

	t.Run("发布v2、重放历史、回滚版本的HTTP语义", func(t *testing.T) {
		testkit.Case(t, "端到端HTTP", "规则发布/重放/回滚")
		code, body := postJSON(t, h, "/v1/rulesets", testkit.RuleSetV2("v2"))
		if code != http.StatusCreated || body["version"] != "v2" {
			t.Fatalf("发布v2失败: %d %v", code, body)
		}
		code, body = postJSON(t, h, "/v1/rulesets", testkit.RuleSetV2("v2"))
		if code != http.StatusConflict {
			t.Fatalf("重复版本应409，实际 %d", code)
		}

		events := eng.AcceptedEvents()
		rb, _ := json.Marshal(map[string]any{"version": "v1", "events": events})
		req := httptest.NewRequest(http.MethodPost, "/v1/replay", bytes.NewReader(rb))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("重放失败: %d", rec.Code)
		}

		code, body = postJSON(t, h, "/v1/rulesets/rollback", map[string]string{"version": "v1"})
		if code != http.StatusOK || body["current"] != "v1" {
			t.Fatalf("回滚失败: %d %v", code, body)
		}
	})

	t.Run("并发处置唯一告警：1个生效其余重复，审计完整", func(t *testing.T) {
		testkit.Case(t, "端到端HTTP", "告警并发处置HTTP语义")
		alerts := eng.Alerts().ListByEvent("evt-1")
		alertID := alerts[0].AlertID

		const n = 20
		var wg sync.WaitGroup
		var mu sync.Mutex
		outcomes := map[string]int{}
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(i int) {
				defer wg.Done()
				reqBody := map[string]string{
					"alert_id":        alertID,
					"idempotency_key": fmt.Sprintf("disp-%02d", i),
					"action":          "acknowledge",
					"actor":           fmt.Sprintf("op%d", i),
				}
				b, _ := json.Marshal(reqBody)
				req := httptest.NewRequest(http.MethodPost, "/v1/alerts/dispose", bytes.NewReader(b))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				var out map[string]any
				_ = json.Unmarshal(rec.Body.Bytes(), &out)
				mu.Lock()
				outcomes[fmt.Sprint(out["outcome"])]++
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		if outcomes["APPLIED"] != 1 || outcomes["DUPLICATE"] != n-1 {
			t.Fatalf("处置结果不符: %v", outcomes)
		}

		req := httptest.NewRequest(http.MethodGet, "/v1/alerts/"+alertID+"/audit", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("审计查询失败: %d", rec.Code)
		}
		var trail []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &trail); err != nil || len(trail) != n {
			t.Fatalf("审计应记录全部%d次尝试，实际 %s", n, rec.Body.String())
		}
	})

}
