package rules

import (
	"fmt"
	"sort"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
)

// Evaluate 针对一个不可变规则集快照求值。
//
// prior 是当前事件之前、按接入顺序排列的已接受事件（不含当前事件）。
// 频次窗口以事件发生时间 OccurredAt 为准：统计同一账户在
// [OccurredAt-Window, OccurredAt] 内（含当前事件）的事件数，
// 因此乱序接入也能得到确定、可复现的结果。
//
// 白名单语义：账户或交易对手命中白名单时直接豁免（exempted=true），
// 不再评估金额、频次、黑名单规则，结论为 PASS。
func Evaluate(rs *RuleSet, event model.TransactionEvent, prior []model.TransactionEvent) (hits []model.Hit, exempted bool) {
	hits = []model.Hit{}

	for _, r := range rs.Rules {
		if !r.Enabled {
			continue
		}
		switch r.Kind {
		case KindList:
			for _, field := range r.MatchOn {
				value := matchValue(field, event)
				if value == "" {
					continue
				}
				listName, ok := rs.listContains(r.ListType, value)
				if !ok {
					continue
				}
				if r.ListType == "white" {
					return []model.Hit{}, true
				}
				hits = append(hits, model.Hit{
					RuleID:      r.ID,
					RuleName:    r.Name,
					RuleVersion: rs.Version,
					Dimension:   "list",
					RiskLevel:   r.RiskLevel,
					Detail:      fmt.Sprintf("%s 命中黑名单[%s]字段[%s]", value, listName, field),
				})
			}
		}
	}
	if exempted {
		return hits, true
	}

	for _, r := range rs.Rules {
		if !r.Enabled {
			continue
		}
		switch r.Kind {
		case KindAmount:
			if event.Amount >= r.MinAmount {
				hits = append(hits, model.Hit{
					RuleID:      r.ID,
					RuleName:    r.Name,
					RuleVersion: rs.Version,
					Dimension:   "amount",
					RiskLevel:   r.RiskLevel,
					Detail:      fmt.Sprintf("金额 %.2f %s 达到阈值 %.2f", event.Amount, event.Currency, r.MinAmount),
				})
			}
		case KindFrequency:
			count := 1
			var matched []model.TransactionEvent
			for _, p := range prior {
				if p.AccountID != event.AccountID {
					continue
				}
				if !p.OccurredAt.Before(event.OccurredAt.Add(-r.Window)) && !p.OccurredAt.After(event.OccurredAt) {
					count++
					matched = append(matched, p)
				}
			}
			if count >= r.Threshold {
				matched = append(matched, event)
				hits = append(hits, model.Hit{
					RuleID:      r.ID,
					RuleName:    r.Name,
					RuleVersion: rs.Version,
					Dimension:   "frequency",
					RiskLevel:   r.RiskLevel,
					Detail: fmt.Sprintf("账户 %s 在 %s 窗口内发生 %d 笔交易，阈值 %d",
						event.AccountID, r.Window, count, r.Threshold),
				})
			}
		}
	}

	// 同一快照内规则顺序固定（按规则集声明顺序），命中输出天然稳定。
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Dimension != hits[j].Dimension {
			return hits[i].Dimension < hits[j].Dimension
		}
		return hits[i].RuleID < hits[j].RuleID
	})
	return hits, false
}

func matchValue(field string, e model.TransactionEvent) string {
	switch field {
	case "account":
		return e.AccountID
	case "counterparty":
		return e.Counterparty
	}
	return ""
}

// HighestLevel 返回命中明细中的最高风险等级，无命中返回 PASS。
func HighestLevel(hits []model.Hit) model.RiskLevel {
	best := model.RiskPass
	for _, h := range hits {
		if model.SeverityRank(h.RiskLevel) > model.SeverityRank(best) {
			best = h.RiskLevel
		}
	}
	return best
}
