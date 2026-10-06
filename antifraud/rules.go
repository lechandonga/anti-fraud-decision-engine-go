package antifraud

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// RuleType identifies the evaluation strategy of a rule.
type RuleType string

const (
	RuleAmountThreshold RuleType = "amount_threshold"
	RuleFrequency       RuleType = "frequency"
	RuleBlacklist       RuleType = "blacklist"
)

// Rule is a single versioned detection rule.
//
//   - amount_threshold: hit when Amount >= Threshold.
//   - frequency: hit when the account has >= Count accepted events
//     (including the current one) within Window ending at OccurredAt.
//   - blacklist: hit when Field (account_id|merchant_id|ip) is in Values.
type Rule struct {
	ID        string        `json:"id"`
	Type      RuleType      `json:"type"`
	Field     string        `json:"field,omitempty"`
	Threshold int64         `json:"threshold,omitempty"`
	Window    time.Duration `json:"window,omitempty"`
	Count     int           `json:"count,omitempty"`
	Values    []string      `json:"values,omitempty"`
	Score     int           `json:"score"`
}

// RuleSet is an immutable, versioned collection of rules.
type RuleSet struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// RuleStore keeps every published rule set so any historical version can be
// replayed, and swaps the active set atomically.
type RuleStore struct {
	mu       sync.RWMutex
	active   RuleSet
	versions map[string]RuleSet
}

func NewRuleStore(initial RuleSet) (*RuleStore, error) {
	s := &RuleStore{versions: map[string]RuleSet{}}
	if err := s.Update(initial); err != nil {
		return nil, err
	}
	return s, nil
}

// Update atomically publishes a new rule set. Version must be new.
func (s *RuleStore) Update(rs RuleSet) error {
	if rs.Version == "" {
		return errors.New("rule set version is required")
	}
	if len(rs.Rules) == 0 {
		return errors.New("rule set must contain at least one rule")
	}
	seen := map[string]bool{}
	for _, r := range rs.Rules {
		if r.ID == "" {
			return errors.New("rule id is required")
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		switch r.Type {
		case RuleAmountThreshold:
			if r.Threshold <= 0 {
				return fmt.Errorf("rule %s: threshold must be positive", r.ID)
			}
		case RuleFrequency:
			if r.Window <= 0 || r.Count < 2 {
				return fmt.Errorf("rule %s: frequency rule needs window>0 and count>=2", r.ID)
			}
		case RuleBlacklist:
			if r.Field != "account_id" && r.Field != "merchant_id" && r.Field != "ip" {
				return fmt.Errorf("rule %s: blacklist field must be account_id, merchant_id or ip", r.ID)
			}
			if len(r.Values) == 0 {
				return fmt.Errorf("rule %s: blacklist values must not be empty", r.ID)
			}
		default:
			return fmt.Errorf("rule %s: unknown type %q", r.ID, r.Type)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.versions[rs.Version]; exists {
		return fmt.Errorf("rule version %q already exists", rs.Version)
	}
	s.versions[rs.Version] = rs
	s.active = rs
	return nil
}

// Active returns the currently active rule set. The returned value is a
// snapshot; a concurrent Update never mutates it.
func (s *RuleStore) Active() RuleSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// Get returns any published version, for replay or rollback.
func (s *RuleStore) Get(version string) (RuleSet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs, ok := s.versions[version]
	return rs, ok
}

// Rollback re-activates a previously published version. Historical decisions
// keep their original version string and are never modified.
func (s *RuleStore) Rollback(version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, ok := s.versions[version]
	if !ok {
		return fmt.Errorf("unknown rule version %q", version)
	}
	s.active = rs
	return nil
}
