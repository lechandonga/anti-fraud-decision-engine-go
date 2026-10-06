package model

import "time"

// RiskLevel 风险等级，数值越大风险越高。
type RiskLevel string

const (
	RiskPass     RiskLevel = "PASS"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
	RiskRejected RiskLevel = "REJECTED"
)

// SeverityRank 返回风险等级的可比较权重。
func SeverityRank(r RiskLevel) int {
	switch r {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	default:
		return 0
	}
}

// TransactionEvent 本地交易事件。EventID 是全局幂等键。
type TransactionEvent struct {
	EventID      string    `json:"event_id"`
	AccountID    string    `json:"account_id"`
	Counterparty string    `json:"counterparty"`
	Amount       float64   `json:"amount"`
	Currency     string    `json:"currency"`
	OccurredAt   time.Time `json:"occurred_at"`
}

// RejectCode 畸形事件的可区分拒绝原因。
type RejectCode string

const (
	RejectMissingEventID      RejectCode = "MISSING_EVENT_ID"
	RejectMissingAccountID    RejectCode = "MISSING_ACCOUNT_ID"
	RejectMissingCurrency     RejectCode = "MISSING_CURRENCY"
	RejectMissingTimestamp    RejectCode = "MISSING_TIMESTAMP"
	RejectAmountInvalid       RejectCode = "INVALID_AMOUNT"
	RejectTimestampInFuture   RejectCode = "TIMESTAMP_IN_FUTURE"
	RejectTimestampTooOld     RejectCode = "TIMESTAMP_TOO_OLD"
	RejectUnsupportedCurrency RejectCode = "UNSUPPORTED_CURRENCY"
)

// Rejection 记录被拒绝接入的事件，保证坏事件不被静默丢弃。
type Rejection struct {
	EventID    string     `json:"event_id"`
	AccountID  string     `json:"account_id"`
	Code       RejectCode `json:"code"`
	Message    string     `json:"message"`
	RejectedAt time.Time  `json:"rejected_at"`
	Raw        any        `json:"raw,omitempty"`
}

// Hit 单条规则命中明细，可解释判定结论。
type Hit struct {
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	RuleVersion string    `json:"rule_version"`
	Dimension   string    `json:"dimension"`
	RiskLevel   RiskLevel `json:"risk_level"`
	Detail      string    `json:"detail"`
}

// Decision 一次事件判定的不可变结论。
type Decision struct {
	EventID        string           `json:"event_id"`
	AccountID      string           `json:"account_id"`
	Seq            int64            `json:"seq"`
	RiskLevel      RiskLevel        `json:"risk_level"`
	Hits           []Hit            `json:"hits"`
	Exempted       bool             `json:"exempted"`
	RuleSetVersion string           `json:"ruleset_version"`
	RuleSetHash    string           `json:"ruleset_hash"`
	EvaluatedAt    time.Time        `json:"evaluated_at"`
	Event          TransactionEvent `json:"event"`
}

// AlertState 告警生命周期状态。
type AlertState string

const (
	AlertOpen         AlertState = "OPEN"
	AlertAcknowledged AlertState = "ACKNOWLEDGED"
	AlertResolved     AlertState = "RESOLVED"
	AlertIgnored      AlertState = "IGNORED"
)

// Alert 同一事件同一规则全局只产生一条告警。
type Alert struct {
	AlertID        string     `json:"alert_id"`
	EventID        string     `json:"event_id"`
	AccountID      string     `json:"account_id"`
	RuleID         string     `json:"rule_id"`
	RuleVersion    string     `json:"rule_version"`
	RuleSetVersion string     `json:"ruleset_version"`
	State          AlertState `json:"state"`
	RiskLevel      RiskLevel  `json:"risk_level"`
	Detail         string     `json:"detail"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// DispositionAction 处置动作。
type DispositionAction string

const (
	ActionAcknowledge DispositionAction = "acknowledge"
	ActionResolve     DispositionAction = "resolve"
	ActionIgnore      DispositionAction = "ignore"
)

// DispositionOutcome 处置请求结果：生效 / 幂等重复 / 被拒绝。
type DispositionOutcome string

const (
	OutcomeApplied   DispositionOutcome = "APPLIED"
	OutcomeDuplicate DispositionOutcome = "DUPLICATE"
	OutcomeRejected  DispositionOutcome = "REJECTED"
)

// AuditEntry 告警状态流转的审计记录。
type AuditEntry struct {
	AlertID        string             `json:"alert_id"`
	IdempotencyKey string             `json:"idempotency_key"`
	Action         DispositionAction  `json:"action"`
	Actor          string             `json:"actor"`
	Reason         string             `json:"reason"`
	FromState      AlertState         `json:"from_state"`
	ToState        AlertState         `json:"to_state"`
	Outcome        DispositionOutcome `json:"outcome"`
	Message        string             `json:"message"`
	ActedAt        time.Time          `json:"acted_at"`
}
