package main

import (
	"log"
	"net/http"
	"strings"

	"dashboard/backend/handlers"
	"dashboard/backend/store"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
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
	// Initialize Database (PostgreSQL with In-Memory fallback)
	store.InitDB()

	mux := http.NewServeMux()

	// Auth Routes
	mux.HandleFunc("/api/auth/request-token", handlers.RequestToken)
	mux.HandleFunc("/api/auth/login", handlers.Login)
	mux.HandleFunc("/api/auth/logout", handlers.Logout)
	mux.HandleFunc("/api/auth/check", handlers.CheckAuth)

	// API Routes
	mux.HandleFunc("/api/summary", handlers.GetSummary)
	mux.HandleFunc("/api/agents", handlers.GetAgents)
	mux.HandleFunc("/api/agents/", handlers.GetAgentDetail) // Handles /api/agents/:id
	mux.HandleFunc("/api/alerts", handlers.GetAlerts)
	mux.HandleFunc("/api/alerts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/analyze") {
			handlers.AnalyzeAlert(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/resolve") {
			handlers.ResolveAlert(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/assign") {
			handlers.AssignAlert(w, r)
		} else {
			handlers.GetAlertDetail(w, r)
		}
	})
	mux.HandleFunc("/api/alerts/bulk-resolve", handlers.BulkResolveAlerts)
	mux.HandleFunc("/api/alerts/bulk-assign", handlers.BulkAssignAlerts)
	mux.HandleFunc("/api/fim", handlers.GetFimEvents)
	mux.HandleFunc("/api/logs", handlers.GetLogs)
	mux.HandleFunc("/api/simulate", handlers.TriggerSimulation)
	mux.HandleFunc("/api/actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodPost {
			handlers.PerformAction(w, r)
		} else {
			handlers.GetActions(w, r)
		}
	})

	// Wrap mux with Auth middleware, then CORS middleware
	handler := corsMiddleware(handlers.AuthMiddleware(mux))

	log.Println("==================================================")
	log.Println("  Aegis Security Operations Center (SOC) API")
	log.Println("  Server starting on http://localhost:8082")
	log.Println("==================================================")

	if err := http.ListenAndServe(":8082", handler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}


