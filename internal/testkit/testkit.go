// Package testkit 提供测试用的确定性构造工具。
package testkit

import (
	"testing"
	"time"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/rules"
)

// Case 记录一个业务用例，便于在 -v 日志中展示覆盖情况。
func Case(t *testing.T, business, caseName string) {
	t.Helper()
	t.Logf("【业务域:%s】用例: %s", business, caseName)
}

// FixedClock 返回固定时间时钟。
func FixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// Base 时间锚点。
var Base = time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)

// Event 快速构造事件。
func Event(id, acct string, amount float64, at time.Time) model.TransactionEvent {
	return model.TransactionEvent{
		EventID:      id,
		AccountID:    acct,
		Counterparty: "CP-1",
		Amount:       amount,
		Currency:     "CNY",
		OccurredAt:   at,
	}
}

// RuleSetV1 构造测试规则集 v1：大额>=50000 HIGH；5分钟3笔 MEDIUM；
// 黑名单 CRITICAL；白名单豁免 LOW 规则等级（但直接豁免）。
func RuleSetV1(version string) *rules.RuleSet {
	return &rules.RuleSet{
		SchemaVersion: rules.SchemaVersion,
		Version:       version,
		Rules: []rules.Rule{
			{ID: "amount-large", Name: "大额", Kind: rules.KindAmount, Enabled: true,
				RiskLevel: model.RiskHigh, MinAmount: 50000},
			{ID: "freq-5m-3", Name: "5分钟3笔", Kind: rules.KindFrequency, Enabled: true,
				RiskLevel: model.RiskMedium, Window: 5 * time.Minute, Threshold: 3},
			{ID: "list-black", Name: "黑名单", Kind: rules.KindList, Enabled: true,
				RiskLevel: model.RiskCritical, ListType: "black",
				MatchOn: []string{"account", "counterparty"}},
			{ID: "list-white", Name: "白名单", Kind: rules.KindList, Enabled: true,
				RiskLevel: model.RiskLow, ListType: "white", MatchOn: []string{"account"}},
		},
		Lists: []rules.List{
			{Name: "black", Type: "black", Entries: []string{"ACCT-BAD"}},
			{Name: "white", Type: "white", Entries: []string{"ACCT-VIP"}},
		},
	}
}

// RuleSetV2 构造 v2：大额阈值放宽到 100000，频次规则禁用，新增币种无关。
func RuleSetV2(version string) *rules.RuleSet {
	rs := RuleSetV1(version)
	rs.Rules[0].MinAmount = 100000
	rs.Rules[1].Enabled = false
	return rs
}
