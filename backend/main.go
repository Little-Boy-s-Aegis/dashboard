package main

import (
	"log"
	"net/http"
	"strings"

	"dashboard/backend/handlers"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow any origin during development, or specifically localhost:5173
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/summary", handlers.GetSummary)
	mux.HandleFunc("/api/agents", handlers.GetAgents)
	mux.HandleFunc("/api/agents/", handlers.GetAgentDetail) // Handles /api/agents/:id
	mux.HandleFunc("/api/alerts", handlers.GetAlerts)
	mux.HandleFunc("/api/alerts/", func(w http.ResponseWriter, r *http.Request) {
		// Route helper for nested alert calls: /api/alerts/:id and /api/alerts/:id/analyze
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/analyze") {
			handlers.AnalyzeAlert(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/resolve") {
			handlers.ResolveAlert(w, r)
		} else {
			handlers.GetAlertDetail(w, r)
		}
	})
	mux.HandleFunc("/api/fim", handlers.GetFimEvents)
	mux.HandleFunc("/api/logs", handlers.GetLogs)
	mux.HandleFunc("/api/simulate", handlers.TriggerSimulation)

	// Wrap mux with CORS middleware
	handler := corsMiddleware(mux)

	log.Println("==================================================")
	log.Println("  Aegis Security Operations Center (SOC) API")
	log.Println("  Server starting on http://localhost:8080")
	log.Println("==================================================")

	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}


