package antifraud

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// IngestResult is the per-event outcome: exactly one of Decision/Rejection.
type IngestResult struct {
	Decision  *Decision  `json:"decision,omitempty"`
	Rejection *Rejection `json:"rejection,omitempty"`
	Alerts    []Alert    `json:"alerts,omitempty"`
}

// Service wires validation, dedup, versioned decisioning and alerting.
// Ingestion is serialized internally so results are deterministic and
// replayable regardless of caller concurrency.
type Service struct {
	mu     sync.Mutex
	rules  *RuleStore
	alerts *AlertStore
	now    func() time.Time

	seen       map[string]bool     // dedup by event_id
	byAccount  map[string][]Event  // accepted events per account, ingest order
	eventOrder []Event             // all accepted events, ingest order
	decisions  map[string]Decision // event_id -> immutable decision
	rejections []Rejection         // all rejections, ingest order
}

func NewService(rules *RuleStore, alerts *AlertStore) *Service {
	return &Service{
		rules:     rules,
		alerts:    alerts,
		now:       time.Now,
		seen:      map[string]bool{},
		byAccount: map[string][]Event{},
		decisions: map[string]Decision{},
	}
}

// SetClock overrides the clock (used by tests and local simulation).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Ingest validates, dedups, scores and alerts on one event. A bad event
// yields a typed Rejection and never affects subsequent events.
func (s *Service) Ingest(e Event) IngestResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ingestLocked(e, s.rules.Active(), true)
}

func (s *Service) ingestLocked(e Event, rs RuleSet, record bool) IngestResult {
	now := s.now()
	if rej := Validate(e, now); rej != nil {
		if record {
			s.rejections = append(s.rejections, *rej)
		}
		return IngestResult{Rejection: rej}
	}
	if s.seen[e.EventID] {
		rej := &Rejection{EventID: e.EventID, Reason: RejectDuplicate, Detail: "event_id already processed"}
		if record {
			s.rejections = append(s.rejections, *rej)
		}
		return IngestResult{Rejection: rej}
	}

	d := Decide(e, s.byAccount[e.AccountID], rs, now)

	s.seen[e.EventID] = true
	s.byAccount[e.AccountID] = append(s.byAccount[e.AccountID], e)
	s.eventOrder = append(s.eventOrder, e)
	s.decisions[e.EventID] = d

	res := IngestResult{Decision: &d}
	for _, h := range d.Hits {
		a, _ := s.alerts.CreateIfAbsent(e.EventID, h.RuleID, rs.Version, now)
		res.Alerts = append(res.Alerts, *a)
	}
	return res
}

// Decision returns the stored immutable decision for an event.
func (s *Service) Decision(eventID string) (Decision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.decisions[eventID]
	return d, ok
}

// Rejections returns all recorded rejections in ingest order.
func (s *Service) Rejections() []Rejection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Rejection, len(s.rejections))
	copy(out, s.rejections)
	return out
}

// Replay re-evaluates all accepted events, in their original ingest order,
// against the given rule version. It never mutates stored state: decisions
// are recomputed on a shadow view. Replaying the version a decision was
// originally made with must reproduce it exactly.
func (s *Service) Replay(version string) ([]Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, ok := s.rules.Get(version)
	if !ok {
		return nil, fmt.Errorf("unknown rule version %q", version)
	}
	byAccount := map[string][]Event{}
	out := make([]Decision, 0, len(s.eventOrder))
	for _, e := range s.eventOrder {
		d := Decide(e, byAccount[e.AccountID], rs, s.now())
		byAccount[e.AccountID] = append(byAccount[e.AccountID], e)
		out = append(out, d)
	}
	return out, nil
}

// VerifyReplay replays the version each decision was made with and returns
// an error if any historical decision differs from its replay.
func (s *Service) VerifyReplay() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := map[string]RuleSet{}
	for _, d := range s.decisions {
		if _, ok := versions[d.RuleVersion]; !ok {
			rs, ok := s.rules.Get(d.RuleVersion)
			if !ok {
				return fmt.Errorf("rule version %q of decision %s no longer available", d.RuleVersion, d.EventID)
			}
			versions[d.RuleVersion] = rs
		}
	}
	byAccount := map[string][]Event{}
	for _, e := range s.eventOrder {
		orig := s.decisions[e.EventID]
		d := Decide(e, byAccount[e.AccountID], versions[orig.RuleVersion], s.now())
		byAccount[e.AccountID] = append(byAccount[e.AccountID], e)
		if d.RuleVersion != orig.RuleVersion || d.Score != orig.Score || d.Risk != orig.Risk || !hitsEqual(d.Hits, orig.Hits) {
			return fmt.Errorf("replay mismatch for event %s", e.EventID)
		}
	}
	return nil
}

func hitsEqual(a, b []Hit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// HandleAlert applies a disposition request to an alert.
func (s *Service) HandleAlert(alertID string, action AlertAction, actor, requestID string) (Alert, HandleResult, error) {
	if action != ActionAcknowledge && action != ActionResolve {
		return Alert{}, "", errors.New("unknown action")
	}
	return s.alerts.Handle(alertID, action, actor, requestID, s.now())
}

// Alerts exposes the alert store for read endpoints.
func (s *Service) Alerts() *AlertStore { return s.alerts }

// Rules exposes the rule store for admin endpoints.
func (s *Service) Rules() *RuleStore { return s.rules }
