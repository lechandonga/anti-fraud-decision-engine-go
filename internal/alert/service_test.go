package alert_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/alert"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/testkit"
)

func sampleHit() model.Hit {
	return model.Hit{
		RuleID: "amount-large", RuleName: "大额", RuleVersion: "v1",
		Dimension: "amount", RiskLevel: model.RiskHigh, Detail: "金额过大",
	}
}

// 业务域：告警去重 —— 同一事件同一规则多次命中只产生一条告警。
func TestAlertRaiseDedup(t *testing.T) {
	svc := alert.NewService(testkit.FixedClock(testkit.Base))

	testkit.Case(t, "告警生命周期", "同事件同规则重复Raise只创建一条")
	a1, created1 := svc.Raise("e1", "ACCT-A", sampleHit(), "v1")
	a2, created2 := svc.Raise("e1", "ACCT-A", sampleHit(), "v1")
	if !created1 || created2 {
		t.Fatalf("首次创建、二次不创建: %v %v", created1, created2)
	}
	if a1.AlertID != a2.AlertID {
		t.Fatalf("告警ID应稳定一致")
	}

	a3, created3 := svc.Raise("e2", "ACCT-A", sampleHit(), "v1")
	if !created3 || a3.AlertID == a1.AlertID {
		t.Fatalf("不同事件应产生不同告警")
	}
}

// 业务域：处置状态机 —— 合法流转、非法拒绝、幂等键重放。
func TestDispositionStateMachine(t *testing.T) {
	svc := alert.NewService(testkit.FixedClock(testkit.Base))
	a, _ := svc.Raise("e1", "ACCT-A", sampleHit(), "v1")

	t.Run("OPEN -> ACKNOWLEDGED 生效并留审计", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "首次确认生效APPLIED")
		res, err := svc.Dispose(alert.DispositionRequest{
			AlertID: a.AlertID, IdempotencyKey: "key-ack",
			Action: model.ActionAcknowledge, Actor: "op1", Reason: "开始核查",
		})
		if err != nil || res.Outcome != model.OutcomeApplied || res.Alert.State != model.AlertAcknowledged {
			t.Fatalf("处置异常: %v %+v", err, res)
		}
	})

	t.Run("相同幂等键重放得到DUPLICATE，状态不变", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "幂等键重放DUPLICATE")
		res, _ := svc.Dispose(alert.DispositionRequest{
			AlertID: a.AlertID, IdempotencyKey: "key-ack",
			Action: model.ActionAcknowledge, Actor: "op1",
		})
		if res.Outcome != model.OutcomeDuplicate {
			t.Fatalf("期望 DUPLICATE，实际 %s", res.Outcome)
		}
	})

	t.Run("新请求重复同一动作（已ACK再ACK）也是DUPLICATE", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "重复确认判DUPLICATE而非报错")
		res, _ := svc.Dispose(alert.DispositionRequest{
			AlertID: a.AlertID, IdempotencyKey: "key-ack-2",
			Action: model.ActionAcknowledge, Actor: "op2",
		})
		if res.Outcome != model.OutcomeDuplicate {
			t.Fatalf("期望 DUPLICATE，实际 %s", res.Outcome)
		}
	})

	t.Run("ACKNOWLEDGED -> RESOLVED 合法", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "确认后可结案")
		res, _ := svc.Dispose(alert.DispositionRequest{
			AlertID: a.AlertID, IdempotencyKey: "key-resolve",
			Action: model.ActionResolve, Actor: "op1", Reason: "确认误报",
		})
		if res.Outcome != model.OutcomeApplied || res.Alert.State != model.AlertResolved {
			t.Fatalf("期望结案生效: %+v", res)
		}
	})

	t.Run("RESOLVED 上的任何新动作被REJECTED", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "终态再处置被REJECTED")
		for _, action := range []model.DispositionAction{model.ActionAcknowledge, model.ActionIgnore} {
			res, _ := svc.Dispose(alert.DispositionRequest{
				AlertID: a.AlertID, IdempotencyKey: fmt.Sprintf("key-final-%s", action),
				Action: action, Actor: "op1",
			})
			if res.Outcome != model.OutcomeRejected {
				t.Fatalf("动作%s 期望 REJECTED，实际 %s", action, res.Outcome)
			}
		}
	})

	t.Run("审计流水完整记录全部尝试", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "审计可追溯每次处置结果")
		trail := svc.AuditTrail(a.AlertID)
		if len(trail) < 5 {
			t.Fatalf("审计记录数量不足: %d", len(trail))
		}
		var applied int
		for _, e := range trail {
			if e.Outcome == model.OutcomeApplied {
				applied++
				if e.FromState == e.ToState {
					t.Fatalf("生效流转前后状态不应相同")
				}
			}
		}
		if applied != 2 {
			t.Fatalf("只有两次生效流转，实际 %d", applied)
		}
	})

	t.Run("缺少幂等键返回错误；不存在告警404语义", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "参数与存在性校验")
		if _, err := svc.Dispose(alert.DispositionRequest{
			AlertID: a.AlertID, Action: model.ActionResolve,
		}); err == nil {
			t.Fatalf("缺少幂等键应报错")
		}
		if _, err := svc.Dispose(alert.DispositionRequest{
			AlertID: "alt_missing", IdempotencyKey: "k", Action: model.ActionResolve,
		}); err != alert.ErrAlertNotFound {
			t.Fatalf("应返回告警不存在，实际 %v", err)
		}
	})
}

// 业务域：并发处置 —— 同动作并发只有一个生效，其余可区分重复/拒绝。
func TestConcurrentDisposition(t *testing.T) {
	t.Run("OPEN告警并发ACK：1个APPLIED，其余全部DUPLICATE", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "20个并发ACK只有1个生效")
		svc := alert.NewService(testkit.FixedClock(testkit.Base))
		a, _ := svc.Raise("e1", "ACCT-A", sampleHit(), "v1")

		const n = 20
		var wg sync.WaitGroup
		counts := map[model.DispositionOutcome]int{}
		var mu sync.Mutex
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(i int) {
				defer wg.Done()
				res, err := svc.Dispose(alert.DispositionRequest{
					AlertID: a.AlertID, IdempotencyKey: fmt.Sprintf("ack-%02d", i),
					Action: model.ActionAcknowledge, Actor: fmt.Sprintf("op%d", i),
				})
				if err != nil {
					t.Errorf("处置错误: %v", err)
					return
				}
				mu.Lock()
				counts[res.Outcome]++
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		if counts[model.OutcomeApplied] != 1 || counts[model.OutcomeDuplicate] != n-1 {
			t.Fatalf("期望1生效%d重复，实际 %v", n-1, counts)
		}
		got, _ := svc.Get(a.AlertID)
		if got.State != model.AlertAcknowledged {
			t.Fatalf("最终状态应为ACKNOWLEDGED: %s", got.State)
		}
	})

	t.Run("ACK告警并发不同动作：恰好一个生效，其余均为可区分的重复或拒绝", func(t *testing.T) {
		testkit.Case(t, "告警并发处置", "并发竞争动作结果合法且可区分")
		svc := alert.NewService(testkit.FixedClock(testkit.Base))
		a, _ := svc.Raise("e2", "ACCT-A", sampleHit(), "v1")
		svc.Dispose(alert.DispositionRequest{
			AlertID: a.AlertID, IdempotencyKey: "init-ack",
			Action: model.ActionAcknowledge, Actor: "op",
		})

		actions := []model.DispositionAction{
			model.ActionAcknowledge, model.ActionResolve, model.ActionIgnore,
		}
		var wg sync.WaitGroup
		outcomes := make([]model.DispositionOutcome, len(actions))
		wg.Add(len(actions))
		for i, act := range actions {
			go func(i int, act model.DispositionAction) {
				defer wg.Done()
				res, err := svc.Dispose(alert.DispositionRequest{
					AlertID: a.AlertID, IdempotencyKey: fmt.Sprintf("race-%s", act),
					Action: act, Actor: "op",
				})
				if err != nil {
					t.Errorf("处置错误: %v", err)
					return
				}
				outcomes[i] = res.Outcome
			}(i, act)
		}
		wg.Wait()
		applied, rejected, duplicate := 0, 0, 0
		for _, o := range outcomes {
			switch o {
			case model.OutcomeApplied:
				applied++
			case model.OutcomeRejected:
				rejected++
			case model.OutcomeDuplicate:
				duplicate++
			}
		}
		if applied != 1 || applied+rejected+duplicate != len(actions) {
			t.Fatalf("终态竞争应有且仅有1生效，其余为重复/拒绝，实际 %v", outcomes)
		}
		got, _ := svc.Get(a.AlertID)
		if got.State != model.AlertResolved && got.State != model.AlertIgnored {
			t.Fatalf("终态只能是RESOLVED或IGNORED: %s", got.State)
		}
	})
}
