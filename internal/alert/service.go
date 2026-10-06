// Package alert 管理告警的生命周期与幂等处置。
//
// 告警以 (事件ID, 规则ID) 为天然唯一键：同一事件重复或乱序到达、
// 同一条规则多次命中，全局只产生一条告警。处置请求携带幂等键，
// 相同请求重复提交返回 DUPLICATE；并发处置时第一个合法请求生效，
// 其余请求根据当前状态返回 DUPLICATE 或 REJECTED，且全程留审计。
package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
)

var ErrAlertNotFound = errors.New("alert not found")

// Clock 便于测试注入确定性时间。
type Clock func() time.Time

// Service 告警存储与处置服务，所有方法并发安全。
type Service struct {
	mu           sync.Mutex
	alerts       map[string]*model.Alert
	key2alert    map[string]string
	dispositions map[string]map[string]dispositionRecord
	audit        []model.AuditEntry
	now          Clock
}

type dispositionRecord struct {
	outcome model.DispositionOutcome
	action  model.DispositionAction
}

func NewService(now Clock) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{
		alerts:       map[string]*model.Alert{},
		key2alert:    map[string]string{},
		dispositions: map[string]map[string]dispositionRecord{},
		now:          now,
	}
}

// AlertID 以事件与规则生成稳定告警ID，保证去重。
func AlertID(eventID, ruleID string) string {
	sum := sha256.Sum256([]byte(eventID + "|" + ruleID))
	return "alt_" + hex.EncodeToString(sum[:12])
}

// Raise 为一次命中创建告警；同一 (事件,规则) 的重复命中返回已有告警且 created=false。
func (s *Service) Raise(eventID, accountID string, hit model.Hit, rulesetVersion string) (*model.Alert, bool) {
	id := AlertID(eventID, hit.RuleID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.alerts[id]; ok {
		return a, false
	}
	now := s.now()
	a := &model.Alert{
		AlertID:        id,
		EventID:        eventID,
		AccountID:      accountID,
		RuleID:         hit.RuleID,
		RuleVersion:    hit.RuleVersion,
		RuleSetVersion: rulesetVersion,
		State:          model.AlertOpen,
		RiskLevel:      hit.RiskLevel,
		Detail:         hit.Detail,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.alerts[id] = a
	s.key2alert[eventID+"|"+hit.RuleID] = id
	return a, true
}

// 合法状态流转表。
var transitions = map[model.AlertState]map[model.DispositionAction]model.AlertState{
	model.AlertOpen: {
		model.ActionAcknowledge: model.AlertAcknowledged,
		model.ActionResolve:     model.AlertResolved,
		model.ActionIgnore:      model.AlertIgnored,
	},
	model.AlertAcknowledged: {
		model.ActionResolve: model.AlertResolved,
		model.ActionIgnore:  model.AlertIgnored,
	},
}

// DispositionRequest 一次处置请求。
type DispositionRequest struct {
	AlertID        string                  `json:"alert_id"`
	IdempotencyKey string                  `json:"idempotency_key"`
	Action         model.DispositionAction `json:"action"`
	Actor          string                  `json:"actor"`
	Reason         string                  `json:"reason"`
}

// DispositionResult 处置结果。
type DispositionResult struct {
	Alert   *model.Alert             `json:"alert"`
	Outcome model.DispositionOutcome `json:"outcome"`
	Audit   model.AuditEntry         `json:"audit"`
}

// Dispose 幂等地处置一条告警。
//
//   - 同一 IdempotencyKey 重放：返回首次结果，记为 DUPLICATE；
//   - 不同请求重复同一已生效动作（如重复 acknowledge）：DUPLICATE；
//   - 当前状态不允许的动作（如对 RESOLVED 再处置）：REJECTED；
//   - 并发下同一告警只有一个请求生效（互斥 + 状态比较）。
func (s *Service) Dispose(req DispositionRequest) (DispositionResult, error) {
	if req.IdempotencyKey == "" {
		return DispositionResult{}, fmt.Errorf("idempotency key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.alerts[req.AlertID]
	if !ok {
		return DispositionResult{}, ErrAlertNotFound
	}

	seen := s.dispositions[req.AlertID]
	if seen == nil {
		seen = map[string]dispositionRecord{}
		s.dispositions[req.AlertID] = seen
	}
	if rec, dup := seen[req.IdempotencyKey]; dup {
		return s.result(a, req, model.OutcomeDuplicate, a.State, a.State,
			fmt.Sprintf("幂等键 %s 已处理，首次结果: %s", req.IdempotencyKey, rec.outcome)), nil
	}

	now := s.now()
	from := a.State
	to, legal := transitions[from][req.Action]
	if !legal {
		// 幂等语义：目标状态已经是该动作会到达的状态，视为重复。
		if sameTarget(from, req.Action) {
			seen[req.IdempotencyKey] = dispositionRecord{outcome: model.OutcomeDuplicate, action: req.Action}
			res := s.result(a, req, model.OutcomeDuplicate, from, from,
				fmt.Sprintf("告警已处于 %s 状态，重复处置", from))
			s.appendAuditLocked(res, now)
			return res, nil
		}
		seen[req.IdempotencyKey] = dispositionRecord{outcome: model.OutcomeRejected, action: req.Action}
		res := s.result(a, req, model.OutcomeRejected, from, from,
			fmt.Sprintf("状态 %s 不允许动作 %s", from, req.Action))
		s.appendAuditLocked(res, now)
		return res, nil
	}

	a.State = to
	a.UpdatedAt = now
	seen[req.IdempotencyKey] = dispositionRecord{outcome: model.OutcomeApplied, action: req.Action}
	res := s.result(a, req, model.OutcomeApplied, from, to, "处置生效")
	s.appendAuditLocked(res, now)
	return res, nil
}

func sameTarget(state model.AlertState, action model.DispositionAction) bool {
	return (state == model.AlertAcknowledged && action == model.ActionAcknowledge) ||
		(state == model.AlertResolved && action == model.ActionResolve) ||
		(state == model.AlertIgnored && action == model.ActionIgnore)
}

func (s *Service) result(a *model.Alert, req DispositionRequest, outcome model.DispositionOutcome,
	from, to model.AlertState, msg string) DispositionResult {
	cp := *a
	return DispositionResult{
		Alert:   &cp,
		Outcome: outcome,
		Audit: model.AuditEntry{
			AlertID:        a.AlertID,
			IdempotencyKey: req.IdempotencyKey,
			Action:         req.Action,
			Actor:          req.Actor,
			Reason:         req.Reason,
			FromState:      from,
			ToState:        to,
			Outcome:        outcome,
			Message:        msg,
			ActedAt:        s.now(),
		},
	}
}

func (s *Service) appendAuditLocked(res DispositionResult, at time.Time) {
	res.Audit.ActedAt = at
	s.audit = append(s.audit, res.Audit)
}

// Get 查询告警快照。
func (s *Service) Get(id string) (*model.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, ErrAlertNotFound
	}
	cp := *a
	return &cp, nil
}

// ListByEvent 返回某事件产生的全部告警。
func (s *Service) ListByEvent(eventID string) []model.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Alert
	for _, a := range s.alerts {
		if a.EventID == eventID {
			out = append(out, *a)
		}
	}
	return out
}

// List 返回全部告警（按创建顺序）。
func (s *Service) List() []model.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		out = append(out, *a)
	}
	return out
}

// AuditTrail 返回告警的完整审计流水。
func (s *Service) AuditTrail(alertID string) []model.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.AuditEntry
	for _, e := range s.audit {
		if e.AlertID == alertID {
			out = append(out, e)
		}
	}
	return out
}
