package antifraud

import (
	"fmt"
	"sort"
	"time"
)

// Hit explains one rule matched by an event.
type Hit struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

// Decision is the immutable, auditable result of evaluating one event
// against one rule version.
type Decision struct {
	EventID     string    `json:"event_id"`
	RuleVersion string    `json:"rule_version"`
	Hits        []Hit     `json:"hits"`
	Score       int       `json:"score"`
	Risk        RiskLevel `json:"risk"`
	DecidedAt   time.Time `json:"decided_at"`
}

const (
	mediumThreshold = 40
	highThreshold   = 80
)

func riskOf(score int) RiskLevel {
	switch {
	case score >= highThreshold:
		return RiskHigh
	case score >= mediumThreshold:
		return RiskMedium
	default:
		return RiskLow
	}
}

// Decide evaluates e against rs. prior contains previously accepted events of
// the same account (used by frequency rules). It is pure: same inputs always
// produce the same Hits/Score/Risk, which makes replay deterministic.
func Decide(e Event, prior []Event, rs RuleSet, now time.Time) Decision {
	d := Decision{EventID: e.EventID, RuleVersion: rs.Version, DecidedAt: now}
	for _, r := range rs.Rules {
		if hit, ok := evalRule(r, e, prior); ok {
			d.Hits = append(d.Hits, hit)
			d.Score += hit.Score
		}
	}
	sort.Slice(d.Hits, func(i, j int) bool { return d.Hits[i].RuleID < d.Hits[j].RuleID })
	d.Risk = riskOf(d.Score)
	return d
}

func evalRule(r Rule, e Event, prior []Event) (Hit, bool) {
	switch r.Type {
	case RuleAmountThreshold:
		if e.Amount >= r.Threshold {
			return Hit{RuleID: r.ID, Score: r.Score,
				Reason: fmt.Sprintf("amount %d >= threshold %d", e.Amount, r.Threshold)}, true
		}
	case RuleFrequency:
		count := 1 // the current event itself
		windowStart := e.OccurredAt.Add(-r.Window)
		for _, p := range prior {
			if !p.OccurredAt.Before(windowStart) && !p.OccurredAt.After(e.OccurredAt) {
				count++
			}
		}
		if count >= r.Count {
			return Hit{RuleID: r.ID, Score: r.Score,
				Reason: fmt.Sprintf("%d events in %s (>= %d)", count, r.Window, r.Count)}, true
		}
	case RuleBlacklist:
		var v string
		switch r.Field {
		case "account_id":
			v = e.AccountID
		case "merchant_id":
			v = e.MerchantID
		case "ip":
			v = e.IP
		}
		for _, banned := range r.Values {
			if v == banned {
				return Hit{RuleID: r.ID, Score: r.Score,
					Reason: fmt.Sprintf("%s %q is blacklisted", r.Field, v)}, true
			}
		}
	}
	return Hit{}, false
}
