// Package rules 实现版本化、不可变的风控规则集。
//
// 规则集（RuleSet）是判定的唯一配置来源：规则与名单都打包在同一个
// 不可变快照内，更新时整包原子替换。判定开始时获取当前快照指针，
// 判定期间即使规则发生变更也不会混用新旧规则。
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
)

const SchemaVersion = 1

// RuleKind 规则维度。
type RuleKind string

const (
	KindAmount    RuleKind = "amount"
	KindFrequency RuleKind = "frequency"
	KindList      RuleKind = "list"
)

// Rule 一条具体规则的配置。名单维度通过 ListType 表达。
type Rule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Kind      RuleKind        `json:"kind"`
	Enabled   bool            `json:"enabled"`
	RiskLevel model.RiskLevel `json:"risk_level"`
	MinAmount float64         `json:"min_amount,omitempty"`
	Window    time.Duration   `json:"window_ns,omitempty"`
	Threshold int             `json:"threshold,omitempty"`
	ListType  string          `json:"list_type,omitempty"`
	MatchOn   []string        `json:"match_on,omitempty"`
}

// List 一个具名名单（黑名单或白名单）。
type List struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Entries []string `json:"entries"`
}

// RuleSet 某一版本的完整判定配置（规则 + 名单），构造后不可变。
type RuleSet struct {
	SchemaVersion int       `json:"schema_version"`
	Version       string    `json:"version"`
	Description   string    `json:"description"`
	ActivatedAt   time.Time `json:"activated_at"`
	Rules         []Rule    `json:"rules"`
	Lists         []List    `json:"lists"`

	hash string
}

// Hash 返回规则集内容的稳定指纹（与字段顺序无关）。
func (rs *RuleSet) Hash() string {
	if rs.hash != "" {
		return rs.hash
	}
	cp := *rs
	sort.SliceStable(cp.Rules, func(i, j int) bool { return cp.Rules[i].ID < cp.Rules[j].ID })
	sort.SliceStable(cp.Lists, func(i, j int) bool { return cp.Lists[i].Name < cp.Lists[j].Name })
	b, _ := json.Marshal(cp)
	sum := sha256.Sum256(b)
	rs.hash = hex.EncodeToString(sum[:16])
	return rs.hash
}

// Validate 校验规则集自身的结构合法性。
func (rs *RuleSet) Validate() error {
	if rs.SchemaVersion != SchemaVersion {
		return errors.New("unsupported ruleset schema version")
	}
	if rs.Version == "" {
		return errors.New("ruleset version is empty")
	}
	seenID := map[string]bool{}
	listByName := map[string]*List{}
	for i := range rs.Lists {
		l := &rs.Lists[i]
		if l.Name == "" {
			return errors.New("list name is empty")
		}
		if l.Type != "black" && l.Type != "white" {
			return errors.New("list type must be black or white: " + l.Name)
		}
		if listByName[l.Name] != nil {
			return errors.New("duplicate list name: " + l.Name)
		}
		listByName[l.Name] = l
	}
	for _, r := range rs.Rules {
		if r.ID == "" {
			return errors.New("rule id is empty")
		}
		if seenID[r.ID] {
			return errors.New("duplicate rule id: " + r.ID)
		}
		seenID[r.ID] = true
		if !r.Enabled {
			continue
		}
		switch r.Kind {
		case KindAmount:
			if r.MinAmount <= 0 {
				return errors.New("amount rule requires positive min_amount: " + r.ID)
			}
		case KindFrequency:
			if r.Window <= 0 || r.Threshold < 2 {
				return errors.New("frequency rule requires positive window and threshold>=2: " + r.ID)
			}
		case KindList:
			if r.ListType != "black" && r.ListType != "white" {
				return errors.New("list rule requires list_type black|white: " + r.ID)
			}
			if len(r.MatchOn) == 0 {
				return errors.New("list rule requires match_on: " + r.ID)
			}
		default:
			return errors.New("unknown rule kind: " + string(r.Kind))
		}
		if model.SeverityRank(r.RiskLevel) == 0 {
			return errors.New("rule requires a valid risk level: " + r.ID)
		}
	}
	return nil
}

// listContains 在指定类型名单中查找成员，返回命中的名单名。
func (rs *RuleSet) listContains(listType, value string) (string, bool) {
	for i := range rs.Lists {
		l := &rs.Lists[i]
		if l.Type != listType {
			continue
		}
		for _, e := range l.Entries {
			if e == value {
				return l.Name, true
			}
		}
	}
	return "", false
}
