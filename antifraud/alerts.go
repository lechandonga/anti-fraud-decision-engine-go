package antifraud

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// AlertStatus is the lifecycle state of an alert.
type AlertStatus string

const (
	AlertOpen         AlertStatus = "OPEN"
	AlertAcknowledged AlertStatus = "ACKNOWLEDGED"
	AlertResolved     AlertStatus = "RESOLVED"
)

// AlertAction is a requested lifecycle transition.
type AlertAction string

const (
	ActionAcknowledge AlertAction = "acknowledge"
	ActionResolve     AlertAction = "resolve"
)

// legalTransitions defines the alert state machine.
var legalTransitions = map[AlertStatus]map[AlertAction]AlertStatus{
	AlertOpen: {
		ActionAcknowledge: AlertAcknowledged,
		ActionResolve:     AlertResolved,
	},
	AlertAcknowledged: {
		ActionResolve: AlertResolved,
	},
}

// Transition is one audited status change.
type Transition struct {
	From      AlertStatus `json:"from"`
	To        AlertStatus `json:"to"`
	Actor     string      `json:"actor"`
	RequestID string      `json:"request_id"`
	At        time.Time   `json:"at"`
}

// Alert is created once per (event, rule) hit pair.
type Alert struct {
	ID          string       `json:"id"`
	EventID     string       `json:"event_id"`
	RuleID      string       `json:"rule_id"`
	RuleVersion string       `json:"rule_version"`
	Status      AlertStatus  `json:"status"`
	History     []Transition `json:"history"`
	CreatedAt   time.Time    `json:"created_at"`
}

// HandleResult classifies the outcome of a disposition request.
type HandleResult string

const (
	// HandleApplied means this request performed the transition.
	HandleApplied HandleResult = "APPLIED"
	// HandleDuplicate means the same request_id was already applied; the
	// alert is returned unchanged (idempotent replay).
	HandleDuplicate HandleResult = "DUPLICATE_REQUEST"
	// HandleConflict means another request already moved the alert to a
	// state from which the requested transition is not legal.
	HandleConflict HandleResult = "CONFLICT"
)

var ErrAlertNotFound = errors.New("alert not found")

// AlertStore stores alerts and serializes disposition per alert.
type AlertStore struct {
	mu        sync.Mutex
	byID      map[string]*Alert
	byEvent   map[string]string // eventID+"|"+ruleID -> alert ID
	processed map[string]bool   // alertID+"|"+requestID
	seq       int
}

func NewAlertStore() *AlertStore {
	return &AlertStore{
		byID:      map[string]*Alert{},
		byEvent:   map[string]string{},
		processed: map[string]bool{},
	}
}

func alertKey(eventID, ruleID string) string { return eventID + "|" + ruleID }

// CreateIfAbsent creates one alert per (event, rule) pair; repeated hits of
// the same event on the same rule return the existing alert.
func (s *AlertStore) CreateIfAbsent(eventID, ruleID, ruleVersion string, now time.Time) (*Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := alertKey(eventID, ruleID)
	if id, ok := s.byEvent[key]; ok {
		return s.byID[id], false
	}
	s.seq++
	a := &Alert{
		ID:          fmt.Sprintf("AL-%06d", s.seq),
		EventID:     eventID,
		RuleID:      ruleID,
		RuleVersion: ruleVersion,
		Status:      AlertOpen,
		CreatedAt:   now,
	}
	s.byID[a.ID] = a
	s.byEvent[key] = a.ID
	return a, true
}

// Get returns a copy of an alert.
func (s *AlertStore) Get(id string) (Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok {
		return Alert{}, false
	}
	return *a, true
}

// List returns copies of all alerts in creation order.
func (s *AlertStore) List() []Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Alert, 0, len(s.byID))
	for i := 1; i <= s.seq; i++ {
		if a, ok := s.byID[fmt.Sprintf("AL-%06d", i)]; ok {
			out = append(out, *a)
		}
	}
	return out
}

// Handle applies a disposition request. Exactly one of concurrent requests
// for the same alert applies; a replayed request_id is idempotent.
func (s *AlertStore) Handle(alertID string, action AlertAction, actor, requestID string, now time.Time) (Alert, HandleResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[alertID]
	if !ok {
		return Alert{}, "", ErrAlertNotFound
	}
	if requestID == "" {
		return Alert{}, "", errors.New("request_id is required")
	}
	if s.processed[alertID+"|"+requestID] {
		return *a, HandleDuplicate, nil
	}
	next, legal := legalTransitions[a.Status][action]
	if !legal {
		return *a, HandleConflict, nil
	}
	a.History = append(a.History, Transition{
		From: a.Status, To: next, Actor: actor, RequestID: requestID, At: now,
	})
	a.Status = next
	s.processed[alertID+"|"+requestID] = true
	return *a, HandleApplied, nil
}
