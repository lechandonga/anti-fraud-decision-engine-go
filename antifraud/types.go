package antifraud

import (
	"fmt"
	"time"
)

// RiskLevel is the final conclusion of a decision.
type RiskLevel string

const (
	RiskLow    RiskLevel = "LOW"
	RiskMedium RiskLevel = "MEDIUM"
	RiskHigh   RiskLevel = "HIGH"
)

// Event is a single transaction event submitted for risk evaluation.
// Amount is expressed in the smallest currency unit (e.g. cents) to avoid
// floating point ambiguity.
type Event struct {
	EventID    string    `json:"event_id"`
	AccountID  string    `json:"account_id"`
	MerchantID string    `json:"merchant_id"`
	IP         string    `json:"ip"`
	Amount     int64     `json:"amount"`
	Currency   string    `json:"currency"`
	OccurredAt time.Time `json:"occurred_at"`
}

// RejectReason classifies why an event was refused before any scoring.
type RejectReason string

const (
	RejectMissingField RejectReason = "MISSING_FIELD"
	RejectBadAmount    RejectReason = "INVALID_AMOUNT"
	RejectBadTimestamp RejectReason = "INVALID_TIMESTAMP"
	RejectDuplicate    RejectReason = "DUPLICATE_EVENT"
)

// Rejection is the recorded outcome for an event that never reached scoring.
type Rejection struct {
	EventID string       `json:"event_id"`
	Reason  RejectReason `json:"reason"`
	Detail  string       `json:"detail"`
}

func (r Rejection) Error() string {
	return fmt.Sprintf("event %q rejected: %s (%s)", r.EventID, r.Reason, r.Detail)
}

// maxEventAge and maxFutureSkew bound acceptable OccurredAt values.
const (
	maxEventAge   = 24 * time.Hour
	maxFutureSkew = 5 * time.Minute
)

// Validate checks an event and returns a typed Rejection or nil.
func Validate(e Event, now time.Time) *Rejection {
	missing := ""
	switch {
	case e.EventID == "":
		missing = "event_id"
	case e.AccountID == "":
		missing = "account_id"
	case e.Currency == "":
		missing = "currency"
	}
	if missing != "" {
		return &Rejection{EventID: e.EventID, Reason: RejectMissingField, Detail: "missing required field: " + missing}
	}
	if e.Amount <= 0 {
		return &Rejection{EventID: e.EventID, Reason: RejectBadAmount, Detail: fmt.Sprintf("amount must be positive, got %d", e.Amount)}
	}
	if e.OccurredAt.IsZero() {
		return &Rejection{EventID: e.EventID, Reason: RejectBadTimestamp, Detail: "occurred_at is zero"}
	}
	if e.OccurredAt.After(now.Add(maxFutureSkew)) {
		return &Rejection{EventID: e.EventID, Reason: RejectBadTimestamp, Detail: "occurred_at is too far in the future"}
	}
	if e.OccurredAt.Before(now.Add(-maxEventAge)) {
		return &Rejection{EventID: e.EventID, Reason: RejectBadTimestamp, Detail: "occurred_at is older than 24h"}
	}
	return nil
}
