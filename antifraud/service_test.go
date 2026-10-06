package antifraud

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func testRules() RuleSet {
	return RuleSet{
		Version: "v1",
		Rules: []Rule{
			{ID: "high-amount", Type: RuleAmountThreshold, Threshold: 1_000_000, Score: 50},
			{ID: "burst", Type: RuleFrequency, Window: 10 * time.Minute, Count: 3, Score: 40},
			{ID: "bad-account", Type: RuleBlacklist, Field: "account_id", Values: []string{"acc-bad"}, Score: 60},
		},
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	rs, err := NewRuleStore(testRules())
	if err != nil {
		t.Fatalf("rule store: %v", err)
	}
	svc := NewService(rs, NewAlertStore())
	svc.SetClock(func() time.Time { return testNow })
	return svc
}

func event(id, account string, amount int64, at time.Time) Event {
	return Event{
		EventID: id, AccountID: account, MerchantID: "m-1", IP: "10.0.0.1",
		Amount: amount, Currency: "CNY", OccurredAt: at,
	}
}

func TestConcurrentIngestion(t *testing.T) {
	t.Log("业务: 并发接入 —— 100 个事件并发提交, 全部判定且频次计数准确")
	svc := newTestService(t)
	const n = 100
	var wg sync.WaitGroup
	results := make([]IngestResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = svc.Ingest(event(fmt.Sprintf("ev-%03d", i), "acc-a", 100, testNow.Add(-time.Minute)))
		}(i)
	}
	wg.Wait()

	decided, burstHits := 0, 0
	for _, r := range results {
		if r.Rejection != nil {
			t.Fatalf("unexpected rejection: %v", r.Rejection)
		}
		decided++
		for _, h := range r.Decision.Hits {
			if h.RuleID == "burst" {
				burstHits++
			}
		}
	}
	if decided != n {
		t.Fatalf("decided %d, want %d", decided, n)
	}
	// burst rule (count>=3) hits from the 3rd event onward: 98 hits.
	if burstHits != n-2 {
		t.Fatalf("burst hits %d, want %d", burstHits, n-2)
	}
	t.Logf("用例通过: %d 个事件全部判定, burst 规则命中 %d 次 (期望 %d)", decided, burstHits, n-2)
}

func TestDuplicateAndOutOfOrderEvents(t *testing.T) {
	t.Log("业务: 重复与乱序事件 —— 重复 event_id 被拒且不重计分, 乱序到达仍按 occurred_at 正确计数")
	svc := newTestService(t)

	r1 := svc.Ingest(event("ev-1", "acc-a", 100, testNow.Add(-5*time.Minute)))
	if r1.Decision == nil {
		t.Fatalf("first ingest rejected: %v", r1.Rejection)
	}
	dup := svc.Ingest(event("ev-1", "acc-a", 100, testNow.Add(-5*time.Minute)))
	if dup.Rejection == nil || dup.Rejection.Reason != RejectDuplicate {
		t.Fatalf("duplicate not detected: %+v", dup)
	}
	if len(dup.Alerts) != 0 {
		t.Fatalf("duplicate produced alerts")
	}

	// Out-of-order: ev-3 occurred before ev-2 but arrives after.
	svc.Ingest(event("ev-2", "acc-a", 100, testNow.Add(-3*time.Minute)))
	r3 := svc.Ingest(event("ev-3", "acc-a", 100, testNow.Add(-4*time.Minute)))
	// ev-3 at t-4min: window covers ev-1 (t-5) and ev-3 -> count 2, no burst.
	for _, h := range r3.Decision.Hits {
		if h.RuleID == "burst" {
			t.Fatalf("out-of-order event wrongly triggered burst: %+v", h)
		}
	}
	// ev-4 at t-2min: window covers ev-1..ev-3 -> count 4 >= 3, burst hits.
	r4 := svc.Ingest(event("ev-4", "acc-a", 100, testNow.Add(-2*time.Minute)))
	found := false
	for _, h := range r4.Decision.Hits {
		if h.RuleID == "burst" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected burst hit for ev-4, got %+v", r4.Decision.Hits)
	}

	// Alerts dedup: same event re-hitting a rule creates only one alert.
	a1, c1 := svc.Alerts().CreateIfAbsent("ev-9", "burst", "v1", testNow)
	a2, c2 := svc.Alerts().CreateIfAbsent("ev-9", "burst", "v1", testNow)
	if !c1 || c2 || a1.ID != a2.ID {
		t.Fatalf("alert dedup failed: %v %v", c1, c2)
	}
	t.Logf("用例通过: 重复事件被拒 (%s), 乱序事件按 occurred_at 计数, 告警按 (event,rule) 去重", dup.Rejection.Reason)
}

func TestMalformedEvents(t *testing.T) {
	t.Log("业务: 畸形事件 —— 缺字段/金额非法/时间戳异常分别给出可区分拒绝原因, 且不污染后续判定")
	svc := newTestService(t)

	cases := []struct {
		name   string
		event  Event
		reason RejectReason
	}{
		{"缺 event_id", event("", "acc-a", 100, testNow), RejectMissingField},
		{"缺 account_id", event("ev-x", "", 100, testNow), RejectMissingField},
		{"缺 currency", Event{EventID: "ev-y", AccountID: "acc-a", Amount: 100, OccurredAt: testNow}, RejectMissingField},
		{"金额为负", event("ev-neg", "acc-a", -5, testNow), RejectBadAmount},
		{"金额为零", event("ev-zero", "acc-a", 0, testNow), RejectBadAmount},
		{"时间戳为零值", event("ev-t0", "acc-a", 100, time.Time{}), RejectBadTimestamp},
		{"时间戳过旧", event("ev-old", "acc-a", 100, testNow.Add(-48*time.Hour)), RejectBadTimestamp},
		{"时间戳过未来", event("ev-fut", "acc-a", 100, testNow.Add(time.Hour)), RejectBadTimestamp},
	}
	for _, tc := range cases {
		res := svc.Ingest(tc.event)
		if res.Rejection == nil {
			t.Fatalf("%s: expected rejection, got decision", tc.name)
		}
		if res.Rejection.Reason != tc.reason {
			t.Fatalf("%s: reason %s, want %s", tc.name, res.Rejection.Reason, tc.reason)
		}
		t.Logf("  用例 %q -> 拒绝原因 %s", tc.name, res.Rejection.Reason)
	}

	// A bad event must not block or pollute subsequent decisions.
	ok := svc.Ingest(event("ev-good", "acc-a", 100, testNow.Add(-time.Minute)))
	if ok.Decision == nil || ok.Decision.Score != 0 {
		t.Fatalf("good event after bad ones misbehaved: %+v", ok)
	}
	if len(svc.Rejections()) != len(cases) {
		t.Fatalf("rejections recorded %d, want %d", len(svc.Rejections()), len(cases))
	}
	t.Logf("用例通过: %d 类畸形事件均被可区分地拒绝, 后续正常事件判定不受影响", len(cases))
}

func TestRuleUpdateAtomicityAndReplay(t *testing.T) {
	t.Log("业务: 规则在线变更与回放 —— 单次判定不混用新旧规则, 决策可追溯版本, 回放一致, 回滚不改历史")
	svc := newTestService(t)

	// Concurrent rule updates while ingesting: every decision must carry a
	// coherent single version.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 2; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			rs := testRules()
			rs.Version = fmt.Sprintf("v%d", i)
			rs.Rules[0].Threshold = int64(1000 * i)
			if err := svc.Rules().Update(rs); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 50; i++ {
		res := svc.Ingest(event(fmt.Sprintf("ev-%d", i), "acc-a", 5000, testNow.Add(-time.Minute)))
		if res.Decision == nil {
			t.Fatalf("unexpected rejection: %v", res.Rejection)
		}
		if _, ok := svc.Rules().Get(res.Decision.RuleVersion); !ok {
			t.Fatalf("decision references unknown rule version %q", res.Decision.RuleVersion)
		}
	}
	close(stop)
	wg.Wait()

	// Historical decisions are reproducible with their own version.
	if err := svc.VerifyReplay(); err != nil {
		t.Fatalf("replay verification failed: %v", err)
	}

	// Replay with v1 gives deterministic, identical results on repeat.
	r1, err := svc.Replay("v1")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.Replay("v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(r1) != len(r2) {
		t.Fatalf("replay length mismatch")
	}
	for i := range r1 {
		if r1[i].Score != r2[i].Score || r1[i].Risk != r2[i].Risk || !hitsEqual(r1[i].Hits, r2[i].Hits) {
			t.Fatalf("replay not deterministic at %d", i)
		}
	}

	// Rollback changes future decisions but never historical ones.
	before, _ := svc.Decision("ev-0")
	if err := svc.Rules().Rollback("v1"); err != nil {
		t.Fatal(err)
	}
	after, _ := svc.Decision("ev-0")
	if before.RuleVersion != after.RuleVersion || before.Score != after.Score ||
		before.Risk != after.Risk || !hitsEqual(before.Hits, after.Hits) {
		t.Fatalf("rollback mutated a historical decision")
	}
	if svc.Rules().Active().Version != "v1" {
		t.Fatalf("rollback did not activate v1")
	}
	t.Logf("用例通过: 50 次判定均绑定单一规则版本, VerifyReplay 一致, 回滚后历史决策不变")
}

func TestAlertLifecycleAndConcurrentHandling(t *testing.T) {
	t.Log("业务: 告警生命周期与幂等处置 —— 合法流转可审计, 重复请求幂等, 并发处置只有一个生效")
	svc := newTestService(t)

	res := svc.Ingest(event("ev-hit", "acc-bad", 100, testNow.Add(-time.Minute)))
	if len(res.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(res.Alerts))
	}
	alertID := res.Alerts[0].ID

	// Illegal transition: RESOLVED is terminal.
	if _, res2, err := svc.HandleAlert(alertID, ActionResolve, "op-1", "req-1"); err != nil || res2 != HandleApplied {
		t.Fatalf("resolve failed: %v %v", res2, err)
	}
	if _, res3, _ := svc.HandleAlert(alertID, ActionAcknowledge, "op-2", "req-2"); res3 != HandleConflict {
		t.Fatalf("expected CONFLICT for illegal transition, got %s", res3)
	}
	// Idempotent replay of req-1.
	a, res4, _ := svc.HandleAlert(alertID, ActionResolve, "op-1", "req-1")
	if res4 != HandleDuplicate || a.Status != AlertResolved {
		t.Fatalf("expected idempotent DUPLICATE_REQUEST, got %s", res4)
	}
	got, _ := svc.Alerts().Get(alertID)
	if len(got.History) != 1 || got.History[0].Actor != "op-1" || got.History[0].To != AlertResolved {
		t.Fatalf("audit history wrong: %+v", got.History)
	}

	// Concurrent disposition on a fresh alert: exactly one APPLIED.
	res = svc.Ingest(event("ev-hit-2", "acc-bad", 100, testNow.Add(-time.Minute)))
	freshID := res.Alerts[0].ID
	const n = 20
	var wg sync.WaitGroup
	outcomes := make([]HandleResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, r, err := svc.HandleAlert(freshID, ActionResolve, fmt.Sprintf("op-%d", i), fmt.Sprintf("req-%d", i))
			if err != nil {
				t.Errorf("handle error: %v", err)
			}
			outcomes[i] = r
		}(i)
	}
	wg.Wait()
	applied, conflicts := 0, 0
	for _, o := range outcomes {
		switch o {
		case HandleApplied:
			applied++
		case HandleConflict:
			conflicts++
		}
	}
	if applied != 1 || applied+conflicts != n {
		t.Fatalf("applied=%d conflicts=%d, want exactly 1 applied and rest conflicts", applied, conflicts)
	}
	final, _ := svc.Alerts().Get(freshID)
	if len(final.History) != 1 {
		t.Fatalf("expected exactly 1 audited transition, got %d", len(final.History))
	}
	t.Logf("用例通过: 非法流转返回 CONFLICT, 重复请求返回 DUPLICATE_REQUEST, %d 并发处置中 1 个生效 %d 个冲突", n, conflicts)
}
