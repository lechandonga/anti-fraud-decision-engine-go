// Command server runs the anti-fraud decision engine as a local HTTP service.
// It is fully self-contained: no external dependencies or services.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lechandonga/anti-fraud-decision-engine-go/antifraud"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func main() {
	rules, err := antifraud.NewRuleStore(antifraud.RuleSet{
		Version: "v1",
		Rules: []antifraud.Rule{
			{ID: "high-amount", Type: antifraud.RuleAmountThreshold, Threshold: 1_000_000, Score: 50},
			{ID: "burst", Type: antifraud.RuleFrequency, Window: 10 * time.Minute, Count: 5, Score: 40},
			{ID: "bad-account", Type: antifraud.RuleBlacklist, Field: "account_id", Values: []string{"acc-blacklisted"}, Score: 60},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	svc := antifraud.NewService(rules, antifraud.NewAlertStore())

	mux := http.NewServeMux()

	// Ingest a transaction event.
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		var e antifraud.Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		res := svc.Ingest(e)
		if res.Rejection != nil {
			writeJSON(w, http.StatusUnprocessableEntity, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	// Look up the immutable decision for an event.
	mux.HandleFunc("GET /decisions/{eventID}", func(w http.ResponseWriter, r *http.Request) {
		d, ok := svc.Decision(r.PathValue("eventID"))
		if !ok {
			writeErr(w, http.StatusNotFound, "decision not found")
			return
		}
		writeJSON(w, http.StatusOK, d)
	})

	// Publish a new rule set (atomic).
	mux.HandleFunc("PUT /rules", func(w http.ResponseWriter, r *http.Request) {
		var rs antifraud.RuleSet
		if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if err := svc.Rules().Update(rs); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, svc.Rules().Active())
	})

	mux.HandleFunc("GET /rules", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Rules().Active())
	})

	// Roll back to a previously published version.
	mux.HandleFunc("POST /rules/rollback/{version}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Rules().Rollback(r.PathValue("version")); err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, svc.Rules().Active())
	})

	// Replay all accepted events against a specific rule version.
	mux.HandleFunc("POST /replay/{version}", func(w http.ResponseWriter, r *http.Request) {
		ds, err := svc.Replay(r.PathValue("version"))
		if err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, ds)
	})

	mux.HandleFunc("GET /alerts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Alerts().List())
	})

	// Idempotent alert disposition: {"action":"acknowledge|resolve","actor":"...","request_id":"..."}
	mux.HandleFunc("POST /alerts/{id}/actions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action    antifraud.AlertAction `json:"action"`
			Actor     string                `json:"actor"`
			RequestID string                `json:"request_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		a, res, err := svc.HandleAlert(r.PathValue("id"), req.Action, req.Actor, req.RequestID)
		switch {
		case errors.Is(err, antifraud.ErrAlertNotFound):
			writeErr(w, http.StatusNotFound, err.Error())
		case err != nil:
			writeErr(w, http.StatusBadRequest, err.Error())
		case res == antifraud.HandleConflict:
			writeJSON(w, http.StatusConflict, map[string]any{"result": res, "alert": a})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"result": res, "alert": a})
		}
	})

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("anti-fraud decision engine listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
