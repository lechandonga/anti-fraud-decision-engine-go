// Package engine 把版本化规则引擎、并发事件接入与告警串联起来。
//
// 并发语义：
//   - EventID 是幂等键：同一事件并发、重复或乱序到达只计分一次、
//     只产生一次告警，后续提交得到首次结论（DUPLICATE）；
//   - 每条新事件在顺序锁内分配单调递增 Seq 并基于“此前已接受事件”
//     求值，因此无论并发如何交错，结论只取决于接入顺序；
//   - 畸形事件不参与计分、不产生告警，但会形成带原因码的拒绝记录，
//     单条坏事件不会阻塞或污染后续事件；
//   - 每次判定固定引用一个不可变规则集版本，可按版本原样重放。
package engine

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/alert"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/rules"
)

// ValidationConfig 事件合法性参数（本地可配置）。
type ValidationConfig struct {
	MaxFutureSkew time.Duration // 允许的时间戳超前量
	MaxEventAge   time.Duration // 允许的时间戳最大历史跨度
	Currencies    map[string]bool
}

// Config 引擎配置。
type Config struct {
	Validation ValidationConfig
	// 达到该风险等级（含）的命中才产生告警。
	AlertMinLevel model.RiskLevel
}

// DefaultConfig 本地模拟的默认配置。
func DefaultConfig() Config {
	return Config{
		Validation: ValidationConfig{
			MaxFutureSkew: 5 * time.Minute,
			MaxEventAge:   30 * 24 * time.Hour,
			Currencies:    map[string]bool{"CNY": true, "USD": true},
		},
		AlertMinLevel: model.RiskMedium,
	}
}

// Status 接入结果分类。
type Status string

const (
	StatusAccepted  Status = "ACCEPTED"
	StatusDuplicate Status = "DUPLICATE"
	StatusRejected  Status = "REJECTED"
)

// Outcome 一次事件提交的结果，三类状态互斥且可区分。
type Outcome struct {
	Status    Status
	Decision  *model.Decision
	Rejection *model.Rejection
	NewAlerts []model.Alert
}

// Engine 风控判定引擎。
type Engine struct {
	store  *rules.Store
	alerts *alert.Service
	cfg    Config
	now    func() time.Time

	orderMu   sync.Mutex
	seq       int64
	accepted  []model.TransactionEvent
	decisions []model.Decision

	guardMu   sync.Mutex
	processed map[string]processedOutcome

	rejectMu   sync.Mutex
	rejections []model.Rejection
}

type processedOutcome struct {
	decision  *model.Decision
	rejection *model.Rejection
}

func New(store *rules.Store, alerts *alert.Service, cfg Config, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	if cfg.AlertMinLevel == "" {
		cfg = DefaultConfig()
	}
	return &Engine{
		store:     store,
		alerts:    alerts,
		cfg:       cfg,
		now:       now,
		processed: map[string]processedOutcome{},
	}
}

var ErrNoRuleSet = errors.New("no active ruleset")

// Ingest 接入一条事件。并发安全，坏事件返回 REJECTED 而不是 error，
// 仅在引擎自身不可用（如无生效规则集）时返回 error。
func (e *Engine) Ingest(ev model.TransactionEvent) (Outcome, error) {
	if ev.EventID != "" {
		if out, dup := e.checkDuplicate(ev.EventID); dup {
			return out, nil
		}
	}

	if code, msg := e.validate(ev); code != "" {
		return e.recordRejection(ev, code, msg)
	}

	rs, err := e.store.Current()
	if err != nil {
		return Outcome{}, ErrNoRuleSet
	}

	// 顺序锁：分配 Seq、固定 prior 快照、求值，保证判定只依赖接入顺序。
	e.orderMu.Lock()
	if ev.EventID != "" {
		if out, dup := e.checkDuplicateLocked(ev.EventID); dup {
			e.orderMu.Unlock()
			return out, nil
		}
	}
	e.seq++
	seq := e.seq
	prior := make([]model.TransactionEvent, len(e.accepted))
	copy(prior, e.accepted)

	hits, exempted := rules.Evaluate(rs, ev, prior)
	level := rules.HighestLevel(hits)
	if exempted {
		level = model.RiskPass
	}
	d := model.Decision{
		EventID:        ev.EventID,
		AccountID:      ev.AccountID,
		Seq:            seq,
		RiskLevel:      level,
		Hits:           hits,
		Exempted:       exempted,
		RuleSetVersion: rs.Version,
		RuleSetHash:    rs.Hash(),
		EvaluatedAt:    e.now(),
		Event:          ev,
	}
	e.accepted = append(e.accepted, ev)
	e.decisions = append(e.decisions, d)
	if ev.EventID != "" {
		e.guardMu.Lock()
		e.processed[ev.EventID] = processedOutcome{decision: &d}
		e.guardMu.Unlock()
	}
	e.orderMu.Unlock()

	out := Outcome{Status: StatusAccepted, Decision: &d}
	for _, h := range hits {
		if model.SeverityRank(h.RiskLevel) < model.SeverityRank(e.cfg.AlertMinLevel) {
			continue
		}
		if a, created := e.alerts.Raise(ev.EventID, ev.AccountID, h, rs.Version); created {
			out.NewAlerts = append(out.NewAlerts, *a)
		}
	}
	return out, nil
}

func (e *Engine) checkDuplicate(id string) (Outcome, bool) {
	e.guardMu.Lock()
	defer e.guardMu.Unlock()
	return e.checkDuplicateLocked(id)
}

func (e *Engine) checkDuplicateLocked(id string) (Outcome, bool) {
	p, ok := e.processed[id]
	if !ok {
		return Outcome{}, false
	}
	return Outcome{Status: StatusDuplicate, Decision: p.decision, Rejection: p.rejection}, true
}

func (e *Engine) recordRejection(ev model.TransactionEvent, code model.RejectCode, msg string) (Outcome, error) {
	r := model.Rejection{
		EventID:    ev.EventID,
		AccountID:  ev.AccountID,
		Code:       code,
		Message:    msg,
		RejectedAt: e.now(),
		Raw:        ev,
	}
	e.rejectMu.Lock()
	e.rejections = append(e.rejections, r)
	e.rejectMu.Unlock()
	if ev.EventID != "" {
		e.guardMu.Lock()
		e.processed[ev.EventID] = processedOutcome{rejection: &r}
		e.guardMu.Unlock()
	}
	return Outcome{Status: StatusRejected, Rejection: &r}, nil
}

// validate 逐字段校验，返回第一个违规原因码，保证原因可区分。
func (e *Engine) validate(ev model.TransactionEvent) (model.RejectCode, string) {
	if ev.EventID == "" {
		return model.RejectMissingEventID, "事件ID缺失"
	}
	if ev.AccountID == "" {
		return model.RejectMissingAccountID, "账户ID缺失"
	}
	if ev.Currency == "" {
		return model.RejectMissingCurrency, "币种缺失"
	}
	if !e.cfg.Validation.Currencies[ev.Currency] {
		return model.RejectUnsupportedCurrency, "不支持的币种: " + ev.Currency
	}
	if ev.Amount <= 0 || math.IsNaN(ev.Amount) || math.IsInf(ev.Amount, 0) {
		return model.RejectAmountInvalid, "金额必须为正数且有限"
	}
	if ev.OccurredAt.IsZero() {
		return model.RejectMissingTimestamp, "交易时间缺失"
	}
	now := e.now()
	if ev.OccurredAt.After(now.Add(e.cfg.Validation.MaxFutureSkew)) {
		return model.RejectTimestampInFuture, "交易时间超出允许的未来时钟偏移"
	}
	if ev.OccurredAt.Before(now.Add(-e.cfg.Validation.MaxEventAge)) {
		return model.RejectTimestampTooOld, "交易时间超出最大历史窗口"
	}
	return "", ""
}

// Replay 使用指定规则版本，按给定接入顺序重放历史事件。
// 不写任何状态、不产生告警；相同输入 + 相同版本必然得到相同结论。
func (e *Engine) Replay(version string, events []model.TransactionEvent) ([]model.Decision, error) {
	rs, err := e.store.Get(version)
	if err != nil {
		return nil, err
	}
	prior := []model.TransactionEvent{}
	out := make([]model.Decision, 0, len(events))
	for _, ev := range events {
		hits, exempted := rules.Evaluate(rs, ev, prior)
		level := rules.HighestLevel(hits)
		if exempted {
			level = model.RiskPass
		}
		out = append(out, model.Decision{
			EventID:        ev.EventID,
			AccountID:      ev.AccountID,
			Seq:            int64(len(out) + 1),
			RiskLevel:      level,
			Hits:           hits,
			Exempted:       exempted,
			RuleSetVersion: rs.Version,
			RuleSetHash:    rs.Hash(),
			EvaluatedAt:    ev.OccurredAt,
			Event:          ev,
		})
		prior = append(prior, ev)
	}
	return out, nil
}

// Decisions 返回接入顺序的全部历史决策（副本）。
func (e *Engine) Decisions() []model.Decision {
	e.orderMu.Lock()
	defer e.orderMu.Unlock()
	out := make([]model.Decision, len(e.decisions))
	copy(out, e.decisions)
	return out
}

// AcceptedEvents 返回已接受事件（接入顺序），供重放使用。
func (e *Engine) AcceptedEvents() []model.TransactionEvent {
	e.orderMu.Lock()
	defer e.orderMu.Unlock()
	out := make([]model.TransactionEvent, len(e.accepted))
	copy(out, e.accepted)
	return out
}

// Rejections 返回全部拒绝记录。
func (e *Engine) Rejections() []model.Rejection {
	e.rejectMu.Lock()
	defer e.rejectMu.Unlock()
	out := make([]model.Rejection, len(e.rejections))
	copy(out, e.rejections)
	return out
}

// Alerts 暴露告警服务，便于处置与查询。
func (e *Engine) Alerts() *alert.Service { return e.alerts }
