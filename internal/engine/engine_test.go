package engine_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/alert"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/engine"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/rules"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/testkit"
)

func newEngine(t *testing.T, rs *rules.RuleSet, now time.Time) *engine.Engine {
	t.Helper()
	store := rules.NewStore()
	if err := store.Publish(rs); err != nil {
		t.Fatalf("发布规则集失败: %v", err)
	}
	return engine.New(store, alert.NewService(testkit.FixedClock(now)), engine.DefaultConfig(),
		testkit.FixedClock(now))
}

// 业务域：规则判定 —— 金额、频次、名单维度给出结论与命中明细。
func TestRuleDimensions(t *testing.T) {
	now := testkit.Base
	eng := newEngine(t, testkit.RuleSetV1("v1"), now)

	t.Run("金额维度: 超过大额阈值判 HIGH 并带命中明细", func(t *testing.T) {
		testkit.Case(t, "规则判定", "大额金额命中HIGH")
		out, err := eng.Ingest(testkit.Event("e-amt", "ACCT-A", 60000, now))
		if err != nil || out.Status != engine.StatusAccepted {
			t.Fatalf("接入失败: %v %+v", err, out)
		}
		if out.Decision.RiskLevel != model.RiskHigh {
			t.Fatalf("期望 HIGH，实际 %s", out.Decision.RiskLevel)
		}
		if out.Decision.RuleSetVersion != "v1" || out.Decision.RuleSetHash == "" {
			t.Fatalf("决策必须记录规则版本与哈希")
		}
		if len(out.Decision.Hits) != 1 || out.Decision.Hits[0].Dimension != "amount" {
			t.Fatalf("命中明细异常: %+v", out.Decision.Hits)
		}
	})

	t.Run("频次维度: 5分钟内第3笔触发频次规则", func(t *testing.T) {
		testkit.Case(t, "规则判定", "窗口频次命中MEDIUM")
		for i, ts := range []time.Time{now.Add(-4 * time.Minute), now.Add(-2 * time.Minute), now} {
			out, _ := eng.Ingest(testkit.Event(fmt.Sprintf("e-freq-%d", i), "ACCT-F", 100, ts))
			if out.Status != engine.StatusAccepted {
				t.Fatalf("第%d笔接入异常: %+v", i, out)
			}
		}
		last := eng.Decisions()[len(eng.Decisions())-1]
		found := false
		for _, h := range last.Hits {
			if h.Dimension == "frequency" {
				found = true
			}
		}
		if !found {
			t.Fatalf("第3笔应命中频次规则: %+v", last.Hits)
		}
	})

	t.Run("名单维度: 黑名单账户 CRITICAL；白名单账户豁免为 PASS", func(t *testing.T) {
		testkit.Case(t, "规则判定", "黑名单CRITICAL与白名单豁免")
		out, _ := eng.Ingest(testkit.Event("e-bad", "ACCT-BAD", 60000, now))
		if out.Decision.RiskLevel != model.RiskCritical {
			t.Fatalf("黑名单应为 CRITICAL，实际 %s", out.Decision.RiskLevel)
		}
		out2, _ := eng.Ingest(testkit.Event("e-vip", "ACCT-VIP", 60000, now))
		if out2.Decision.RiskLevel != model.RiskPass || !out2.Decision.Exempted || len(out2.Decision.Hits) != 0 {
			t.Fatalf("白名单应豁免为 PASS 且无命中: %+v", out2.Decision)
		}
	})
}

// 业务域：乱序事件 —— 频次按事件时间窗口计算，乱序接入结论确定且只计一次。
func TestOutOfOrderEvents(t *testing.T) {
	now := testkit.Base
	eng := newEngine(t, testkit.RuleSetV1("v1"), now)
	testkit.Case(t, "乱序事件", "事件按 e1,e0,e2 乱序接入（最晚事件最后到），频次结论确定")

	t0, t1, t2 := now.Add(-4*time.Minute), now.Add(-2*time.Minute), now
	order := []struct {
		id string
		ts time.Time
	}{
		{"e1", t1}, {"e0", t0}, {"e2", t2},
	}
	for _, o := range order {
		out, _ := eng.Ingest(testkit.Event(o.id, "ACCT-OO", 100, o.ts))
		if out.Status != engine.StatusAccepted {
			t.Fatalf("乱序接入失败: %+v", out)
		}
	}
	// 按接入顺序 Seq=3 是 e2；其事件时间窗口含 e0,e1,e2，应命中频次。
	last := eng.Decisions()[2]
	if last.EventID != "e2" {
		t.Fatalf("Seq=3 应为 e2，实际 %s", last.EventID)
	}
	found := false
	for _, h := range last.Hits {
		if h.Dimension == "frequency" {
			found = true
		}
	}
	if !found {
		t.Fatalf("最晚事件到达时应回看窗口命中频次（以事件时间计窗）")
	}

	var wg sync.WaitGroup
	dups := int64(0)
	mu := &sync.Mutex{}
	for _, o := range order[:2] {
		wg.Add(1)
		go func(id string, ts time.Time) {
			defer wg.Done()
			out, _ := eng.Ingest(testkit.Event(id, "ACCT-OO", 100, ts))
			mu.Lock()
			if out.Status == engine.StatusDuplicate {
				dups++
			}
			mu.Unlock()
		}(o.id, o.ts)
	}
	wg.Wait()
	if dups != 2 || len(eng.Decisions()) != 3 {
		t.Fatalf("乱序重复事件应全部判重，决策仍为3条，实际 dups=%d decisions=%d", dups, len(eng.Decisions()))
	}
}

// 业务域：畸形事件 —— 不同坏数据给出可区分原因，不阻塞后续、不参与计分。
func TestMalformedEvents(t *testing.T) {
	now := testkit.Base
	eng := newEngine(t, testkit.RuleSetV1("v1"), now)
	good := testkit.Event("e-good", "ACCT-G", 100, now)

	cases := []struct {
		name string
		ev   model.TransactionEvent
		code model.RejectCode
	}{
		{"缺少事件ID", model.TransactionEvent{AccountID: "a", Amount: 1, Currency: "CNY", OccurredAt: now}, model.RejectMissingEventID},
		{"缺少账户ID", mutate(good, "m1", func(e *model.TransactionEvent) { e.AccountID = "" }), model.RejectMissingAccountID},
		{"缺少币种", mutate(good, "m2", func(e *model.TransactionEvent) { e.Currency = "" }), model.RejectMissingCurrency},
		{"不支持币种", mutate(good, "m3", func(e *model.TransactionEvent) { e.Currency = "XXX" }), model.RejectUnsupportedCurrency},
		{"金额为零", mutate(good, "m4", func(e *model.TransactionEvent) { e.Amount = 0 }), model.RejectAmountInvalid},
		{"金额为负", mutate(good, "m5", func(e *model.TransactionEvent) { e.Amount = -10 }), model.RejectAmountInvalid},
		{"时间缺失", mutate(good, "m6", func(e *model.TransactionEvent) { e.OccurredAt = time.Time{} }), model.RejectMissingTimestamp},
		{"时间在未来", mutate(good, "m7", func(e *model.TransactionEvent) { e.OccurredAt = now.Add(time.Hour) }), model.RejectTimestampInFuture},
		{"时间过于久远", mutate(good, "m8", func(e *model.TransactionEvent) { e.OccurredAt = now.Add(-31 * 24 * time.Hour) }), model.RejectTimestampTooOld},
	}

	for _, c := range cases {
		t.Run("畸形事件: "+c.name, func(t *testing.T) {
			testkit.Case(t, "畸形事件", c.name+" => "+string(c.code))
			out, err := eng.Ingest(c.ev)
			if err != nil {
				t.Fatalf("坏事件不应返回Go错误，而应是REJECTED: %v", err)
			}
			if out.Status != engine.StatusRejected || out.Rejection.Code != c.code {
				t.Fatalf("期望拒绝原因 %s，实际 %+v", c.code, out.Rejection)
			}
		})
	}

	t.Run("坏事件之后正常事件仍可判定，坏事件不参与频次计分", func(t *testing.T) {
		testkit.Case(t, "畸形事件", "坏事件不污染后续判定")
		for i := 0; i < 3; i++ {
			bad := good
			bad.EventID = fmt.Sprintf("bad-seq-%d", i)
			bad.Amount = -1
			if out, _ := eng.Ingest(bad); out.Status != engine.StatusRejected {
				t.Fatalf("应拒绝")
			}
		}
		out, _ := eng.Ingest(good)
		if out.Status != engine.StatusAccepted || out.Decision.Seq != 1 {
			t.Fatalf("坏事件不得计入Seq，正常事件 Seq 应为1: %+v", out)
		}
	})

	t.Run("带ID的坏事件重复提交同样判重，原因可追溯", func(t *testing.T) {
		testkit.Case(t, "畸形事件", "坏事件重复提交幂等")
		bad := good
		bad.EventID = "bad-dup"
		bad.Amount = 0
		out1, _ := eng.Ingest(bad)
		out2, _ := eng.Ingest(bad)
		if out1.Status != engine.StatusRejected || out2.Status != engine.StatusDuplicate {
			t.Fatalf("首次拒绝、重复判重: %s %s", out1.Status, out2.Status)
		}
		if out2.Rejection == nil || out2.Rejection.Code != model.RejectAmountInvalid {
			t.Fatalf("重复的坏事件也应能追溯拒绝原因")
		}
	})
}

func mutate(base model.TransactionEvent, id string, fn func(*model.TransactionEvent)) model.TransactionEvent {
	e := base
	e.EventID = id
	fn(&e)
	return e
}

// 业务域：规则变更与回放 —— 原子生效、同版本重放一致、回滚不改历史。
func TestRuleVersioningAndReplay(t *testing.T) {
	now := testkit.Base
	store := rules.NewStore()
	if err := store.Publish(testkit.RuleSetV1("v1")); err != nil {
		t.Fatal(err)
	}
	eng := engine.New(store, alert.NewService(testkit.FixedClock(now)), engine.DefaultConfig(),
		testkit.FixedClock(now))

	events := []model.TransactionEvent{
		testkit.Event("h0", "ACCT-H", 60000, now.Add(-4*time.Minute)),
		testkit.Event("h1", "ACCT-H", 100, now.Add(-2*time.Minute)),
		testkit.Event("h2", "ACCT-H", 100, now),
	}
	for _, ev := range events {
		eng.Ingest(ev)
	}
	v1Decisions := eng.Decisions()

	t.Run("在线发布v2后新决策用v2，历史决策仍引用v1", func(t *testing.T) {
		testkit.Case(t, "规则变更与回放", "v2原子生效，历史不变")
		if err := store.Publish(testkit.RuleSetV2("v2")); err != nil {
			t.Fatal(err)
		}
		out, _ := eng.Ingest(testkit.Event("h3", "ACCT-H", 60000, now.Add(time.Minute)))
		if out.Decision.RuleSetVersion != "v2" {
			t.Fatalf("新事件必须按v2判定")
		}
		if out.Decision.RiskLevel != model.RiskPass {
			t.Fatalf("v2放宽阈值后该金额应PASS，实际 %s", out.Decision.RiskLevel)
		}
		for _, d := range v1Decisions {
			if d.RuleSetVersion != "v1" {
				t.Fatalf("历史决策版本不得被改写: %+v", d)
			}
		}
	})

	t.Run("同版本重放历史事件，结论与原始完全一致", func(t *testing.T) {
		testkit.Case(t, "规则变更与回放", "v1重放结论逐字段一致")
		replayed, err := eng.Replay("v1", events)
		if err != nil {
			t.Fatal(err)
		}
		if len(replayed) != len(v1Decisions) {
			t.Fatalf("重放数量不一致")
		}
		for i := range v1Decisions {
			assertSameDecision(t, v1Decisions[i], replayed[i])
		}
	})

	t.Run("用v2重放同一批事件，结论不同且可预期", func(t *testing.T) {
		testkit.Case(t, "规则变更与回放", "v2重放差异可预期")
		replayed, _ := eng.Replay("v2", events)
		if replayed[0].RiskLevel != model.RiskPass {
			t.Fatalf("v2下60000不应命中大额: %s", replayed[0].RiskLevel)
		}
		if replayed[2].RiskLevel != model.RiskPass {
			t.Fatalf("v2禁用频次规则，第3笔应PASS: %+v", replayed[2].Hits)
		}
	})

	t.Run("重复重放结果稳定：两次Replay逐字段一致", func(t *testing.T) {
		testkit.Case(t, "规则变更与回放", "重放可重复")
		a, _ := eng.Replay("v1", events)
		b, _ := eng.Replay("v1", events)
		for i := range a {
			assertSameDecision(t, a[i], b[i])
		}
	})

	t.Run("回滚到v1只影响新判定，历史决策保持不变", func(t *testing.T) {
		testkit.Case(t, "规则变更与回放", "回滚不改写历史")
		before := eng.Decisions()
		if _, err := store.Rollback("v1"); err != nil {
			t.Fatal(err)
		}
		out, _ := eng.Ingest(testkit.Event("h4", "ACCT-H", 60000, now.Add(2*time.Minute)))
		if out.Decision.RuleSetVersion != "v1" || out.Decision.RiskLevel != model.RiskHigh {
			t.Fatalf("回滚后新事件应按v1命中大额: %+v", out.Decision)
		}
		after := eng.Decisions()
		for i := range before {
			assertSameDecision(t, before[i], after[i])
		}
	})

	t.Run("发布重复版本被拒绝；不存在版本不能回滚/重放", func(t *testing.T) {
		testkit.Case(t, "规则变更与回放", "版本完整性校验")
		if err := store.Publish(testkit.RuleSetV1("v1")); err != rules.ErrVersionExists {
			t.Fatalf("重复版本应报错，实际 %v", err)
		}
		if _, err := store.Rollback("nope"); err != rules.ErrVersionAbsent {
			t.Fatalf("不存在版本回滚应报错，实际 %v", err)
		}
		if _, err := eng.Replay("nope", events); err != rules.ErrVersionAbsent {
			t.Fatalf("不存在版本重放应报错，实际 %v", err)
		}
	})
}

func assertSameDecision(t *testing.T, want, got model.Decision) {
	t.Helper()
	if want.EventID != got.EventID || want.RiskLevel != got.RiskLevel ||
		want.RuleSetVersion != got.RuleSetVersion || want.RuleSetHash != got.RuleSetHash ||
		want.Exempted != got.Exempted || len(want.Hits) != len(got.Hits) {
		t.Fatalf("决策不一致:\nwant=%+v\ngot =%+v", want, got)
	}
	for i := range want.Hits {
		if want.Hits[i] != got.Hits[i] {
			t.Fatalf("命中明细不一致:\nwant=%+v\ngot =%+v", want.Hits, got.Hits)
		}
	}
}

// 业务域：并发接入 —— 同一事件并发提交只计分一次。
func TestConcurrentDeduplication(t *testing.T) {
	now := testkit.Base
	eng := newEngine(t, testkit.RuleSetV1("v1"), now)
	ev := testkit.Event("e-conc", "ACCT-C", 100, now)

	testkit.Case(t, "并发接入", "同一事件50个并发请求只接受1次")
	const n = 50
	var wg sync.WaitGroup
	var accepted, duplicate int64
	mu := &sync.Mutex{}
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			out, err := eng.Ingest(ev)
			if err != nil {
				t.Errorf("接入返回错误: %v", err)
				return
			}
			mu.Lock()
			switch out.Status {
			case engine.StatusAccepted:
				accepted++
			case engine.StatusDuplicate:
				duplicate++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if accepted != 1 || duplicate != n-1 {
		t.Fatalf("期望 1 接受 %d 重复，实际 %d 接受 %d 重复", n-1, accepted, duplicate)
	}
	if len(eng.Decisions()) != 1 {
		t.Fatalf("重复事件不得产生多条决策")
	}

	t.Run("重复提交返回首次结论，Seq与版本一致", func(t *testing.T) {
		testkit.Case(t, "并发接入", "重复提交返回同一决策")
		out, _ := eng.Ingest(ev)
		if out.Status != engine.StatusDuplicate || out.Decision.Seq != 1 {
			t.Fatalf("重复提交应返回首次决策(Seq=1): %+v", out)
		}
	})
}
