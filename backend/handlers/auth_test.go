package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"
)

// Helper: clear stores before each test
func setupTestStores() {
	authMu.Lock()
	defer authMu.Unlock()
	otpStore = make(map[string]otpData)
	sessionStore = make(map[string]sessionData)
	lockoutStore = make(map[string]lockoutData)
	store.UsePostgres = false
}

func TestGenerateSecureSHA256Token(t *testing.T) {
	t.Run("Generates 64 character hex string", func(t *testing.T) {
		token := generateSecureSHA256Token()
		if len(token) != 64 {
			t.Errorf("Expected token length of 64, got %d", len(token))
		}
		// Assert hexadecimal characters only
		for _, char := range token {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				t.Errorf("Unexpected character in hex token: %c", char)
			}
		}
	})
}

func TestRequestTokenHandler(t *testing.T) {
	setupTestStores()

	t.Run("Method Not Allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/auth/request-token", nil)
		w := httptest.NewRecorder()

		RequestToken(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})

	t.Run("Empty Payload", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString("{}"))
		w := httptest.NewRecorder()

		RequestToken(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Invalid UID - Length", func(t *testing.T) {
		payload := `{"uid":"101"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		RequestToken(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "exactly 5 digits") {
			t.Errorf("Expected error details about length, got: %s", w.Body.String())
		}
	})

	t.Run("Invalid UID - Characters", func(t *testing.T) {
		payload := `{"uid":"10abc"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		RequestToken(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "only numbers") {
			t.Errorf("Expected error details about digits, got: %s", w.Body.String())
		}
	})

	t.Run("Account Enumeration / Non-existent UID", func(t *testing.T) {
		payload := `{"uid":"99999"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		RequestToken(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Invalid login request") {
			t.Errorf("Expected generic login error, got: %s", w.Body.String())
		}
	})

	t.Run("Success Request Token for 10001 (admin)", func(t *testing.T) {
		payload := `{"uid":"10001"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		RequestToken(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var res models.AuthResponse
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal("Failed to parse response")
		}

		if res.UID != "10001" || res.Username != "admin" {
			t.Errorf("Expected UID 10001 and admin, got UID %s, Username %s", res.UID, res.Username)
		}
		if len(res.Token) != 64 {
			t.Errorf("Expected SHA-256 token, got length %d", len(res.Token))
		}
	})
}

func TestLoginHandler(t *testing.T) {
	setupTestStores()

	// Pre-seed an OTP token for UID 10001 (admin)
	authMu.Lock()
	otpStore["10001"] = otpData{
		Token:     "test-sha256-otp-token-value-here-64-characters-long",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	authMu.Unlock()

	t.Run("Method Not Allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/auth/login", nil)
		w := httptest.NewRecorder()

		Login(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})

	t.Run("Incorrect OTP Token", func(t *testing.T) {
		payload := `{"uid":"10001","token":"wrong-token"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()

		Login(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("Brute-Force Lockout Trigger", func(t *testing.T) {
		// Mock 5 failed attempts
		lockKey := "10001@192.0.2.1"
		authMu.Lock()
		lockoutStore[lockKey] = lockoutData{
			FailedAttempts: 5,
			BlockedUntil:   time.Now().Add(15 * time.Minute),
		}
		authMu.Unlock()

		payload := `{"uid":"10001","token":"wrong-token"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()

		Login(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 Forbidden on lockout, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "temporarily locked") {
			t.Errorf("Expected lockout message, got: %s", w.Body.String())
		}
	})

	t.Run("Successful Login", func(t *testing.T) {
		// Reset lock and seed active OTP
		authMu.Lock()
		delete(lockoutStore, "10001@192.0.2.2")
		otpStore["10001"] = otpData{
			Token:     "correct-token",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		authMu.Unlock()

		payload := `{"uid":"10001","token":"correct-token"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		req.RemoteAddr = "192.0.2.2:1234"
		w := httptest.NewRecorder()

		Login(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var res models.LoginResponse
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal("Failed to parse login response")
		}

		if res.Username != "admin" {
			t.Errorf("Expected admin, got %s", res.Username)
		}

		// Verify cookie was set
		cookies := w.Result().Cookies()
		var foundCookie bool
		for _, c := range cookies {
			if c.Name == "session_token" && c.Value == res.SessionToken {
				foundCookie = true
				if !c.HttpOnly {
					t.Error("Expected HttpOnly cookie to be set")
				}
			}
		}
		if !foundCookie {
			t.Error("Expected session_token cookie to be set")
		}

		// Verify OTP was consumed
		authMu.RLock()
		_, otpExists := otpStore["10001"]
		authMu.RUnlock()
		if otpExists {
			t.Error("Expected OTP token to be consumed/deleted upon successful login")
		}
	})
}

func TestCheckAuthAndSessionHijacking(t *testing.T) {
	setupTestStores()

	// Pre-seed a session
	sessionToken := "valid-session-token"
	authMu.Lock()
	sessionStore[sessionToken] = sessionData{
		UID:       "10001",
		Username:  "admin",
		IPAddress: "192.0.2.5",
		ExpiresAt: time.Now().Add(8 * time.Hour),
	}
	authMu.Unlock()

	t.Run("Verify Valid Session from Same IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
		req.RemoteAddr = "192.0.2.5:1234"
		w := httptest.NewRecorder()

		CheckAuth(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var status models.AuthStatus
		json.Unmarshal(w.Body.Bytes(), &status)

		if !status.IsAuthenticated || status.Username != "admin" {
			t.Errorf("Expected authenticated as admin, got %+v", status)
		}
	})

	t.Run("Hijacking Prevention - IP Mismatch Revocation", func(t *testing.T) {
		// Attempt access from different IP address
		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
		req.RemoteAddr = "203.0.113.88:1234" // Hijacker's IP
		w := httptest.NewRecorder()

		CheckAuth(w, req)

		var status models.AuthStatus
		json.Unmarshal(w.Body.Bytes(), &status)

		if status.IsAuthenticated {
			t.Error("Expected authentication to fail due to IP hijacking check")
		}

		// Verify session was revoked/deleted completely
		authMu.RLock()
		_, exists := sessionStore[sessionToken]
		authMu.RUnlock()
		if exists {
			t.Error("Expected session to be completely revoked and deleted from store upon IP mismatch detection")
		}
	})
}
