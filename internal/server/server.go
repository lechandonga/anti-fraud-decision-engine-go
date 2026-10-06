// Package server 暴露本地 HTTP 接口，全部数据保存在内存中，无外部依赖。
package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/alert"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/engine"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/model"
	"github.com/lechandonga/anti-fraud-decision-engine-go/internal/rules"
)

type Server struct {
	Engine *engine.Engine
	Store  *rules.Store
	Mux    *http.ServeMux
}

func New(eng *engine.Engine, store *rules.Store) *Server {
	s := &Server{Engine: eng, Store: store, Mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.Mux.HandleFunc("POST /v1/events", s.handleIngest)
	s.Mux.HandleFunc("GET /v1/decisions", s.handleDecisions)
	s.Mux.HandleFunc("GET /v1/rejections", s.handleRejections)
	s.Mux.HandleFunc("POST /v1/rulesets", s.handlePublish)
	s.Mux.HandleFunc("GET /v1/rulesets", s.handleListRuleSets)
	s.Mux.HandleFunc("POST /v1/rulesets/rollback", s.handleRollback)
	s.Mux.HandleFunc("POST /v1/replay", s.handleReplay)
	s.Mux.HandleFunc("GET /v1/alerts", s.handleListAlerts)
	s.Mux.HandleFunc("POST /v1/alerts/dispose", s.handleDispose)
	s.Mux.HandleFunc("GET /v1/alerts/{id}/audit", s.handleAudit)
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var ev model.TransactionEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体不是合法JSON: " + err.Error()})
		return
	}
	out, err := s.Engine.Ingest(ev)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	status := http.StatusOK
	if out.Status == engine.StatusRejected {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, out)
}

func (s *Server) handleDecisions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Engine.Decisions())
}

func (s *Server) handleRejections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Engine.Rejections())
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	var rs rules.RuleSet
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "规则集JSON非法: " + err.Error()})
		return
	}
	if err := s.Store.Publish(&rs); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, rules.ErrVersionExists) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"version": rs.Version, "hash": rs.Hash(), "versions": s.Store.Versions(),
	})
}

func (s *Server) handleListRuleSets(w http.ResponseWriter, _ *http.Request) {
	cur, _ := s.Store.Current()
	resp := map[string]any{"versions": s.Store.Versions()}
	if cur != nil {
		resp["current"] = cur.Version
		resp["hash"] = cur.Hash()
	}
	writeJSON(w, http.StatusOK, resp)
}

type rollbackReq struct {
	Version string `json:"version"`
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	var req rollbackReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "需要指定 version"})
		return
	}
	rs, err := s.Store.Rollback(req.Version)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"current": rs.Version, "hash": rs.Hash()})
}

type replayReq struct {
	Version    string                   `json:"version"`
	Events     []model.TransactionEvent `json:"events"`
	UseHistory bool                     `json:"use_history"`
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	var req replayReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	events := req.Events
	if req.UseHistory {
		events = s.Engine.AcceptedEvents()
	}
	decisions, err := s.Engine.Replay(req.Version, events)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, decisions)
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	if eventID := r.URL.Query().Get("event_id"); eventID != "" {
		writeJSON(w, http.StatusOK, s.Engine.Alerts().ListByEvent(eventID))
		return
	}
	writeJSON(w, http.StatusOK, s.Engine.Alerts().List())
}

func (s *Server) handleDispose(w http.ResponseWriter, r *http.Request) {
	var req alert.DispositionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	res, err := s.Engine.Alerts().Dispose(req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, alert.ErrAlertNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	status := http.StatusOK
	if res.Outcome == model.OutcomeRejected {
		status = http.StatusConflict
	}
	writeJSON(w, status, res)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.Engine.Alerts().Get(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.Engine.Alerts().AuditTrail(id))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
