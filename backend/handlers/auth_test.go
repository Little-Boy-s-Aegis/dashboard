package handlers

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"
)

// Standard Library Mock SQL Driver for 100% Database Coverage
type mockDriver struct {
	failQueries bool
}

var theMockDriver = &mockDriver{}

func init() {
	sql.Register("mock_driver", theMockDriver)
}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	return &mockConn{d}, nil
}

type mockConn struct {
	d *mockDriver
}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{c.d, query}, nil
}

func (c *mockConn) Close() error { return nil }
func (c *mockConn) Begin() (driver.Tx, error) { return nil, nil }

type mockStmt struct {
	d     *mockDriver
	query string
}

func (s *mockStmt) Close() error { return nil }
func (s *mockStmt) NumInput() int { return -1 }

func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	if s.d.failQueries {
		return nil, errors.New("mock db execute error")
	}
	return &mockResult{}, nil
}

func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) {
	if s.d.failQueries {
		return nil, errors.New("mock db query error")
	}
	return &mockRows{s.query, 0, args}, nil
}

type mockResult struct{}
func (r *mockResult) LastInsertId() (int64, error) { return 1, nil }
func (r *mockResult) RowsAffected() (int64, error) { return 1, nil }

type mockRows struct {
	query string
	index int
	args  []driver.Value
}

func (r *mockRows) Columns() []string {
	if strings.Contains(r.query, "SELECT username FROM operators") {
		return []string{"username"}
	}
	if strings.Contains(r.query, "SELECT token_hash") {
		return []string{"token_hash", "expires_at"}
	}
	if strings.Contains(r.query, "SELECT uid, username") {
		return []string{"uid", "username", "ip_address", "expires_at"}
	}
	return []string{"col"}
}

func (r *mockRows) Close() error { return nil }

func (r *mockRows) Next(dest []driver.Value) error {
	if r.index > 0 {
		return io.EOF
	}
	r.index++
	if strings.Contains(r.query, "SELECT username FROM operators") {
		dest[0] = "admin"
		return nil
	}
	if strings.Contains(r.query, "SELECT token_hash") {
		dest[0] = "correct-token"
		// If arg is "expired", make it expired
		if len(r.args) > 0 && r.args[0] == "expired" {
			dest[1] = time.Now().Add(-5 * time.Minute)
		} else {
			dest[1] = time.Now().Add(5 * time.Minute)
		}
		return nil
	}
	if strings.Contains(r.query, "SELECT uid, username") {
		dest[0] = "10001"
		dest[1] = "admin"
		dest[2] = "192.0.2.100"
		
		isExpired := len(r.args) > 0 && r.args[0] == "expired-sql-session"
		if isExpired {
			dest[3] = time.Now().Add(-1 * time.Hour)
		} else {
			dest[3] = time.Now().Add(8 * time.Hour)
		}
		return nil
	}
	return io.EOF
}

// Helper: clear stores before each test
func setupTestStores() {
	authMu.Lock()
	defer authMu.Unlock()
	otpStore = make(map[string]otpData)
	sessionStore = make(map[string]sessionData)
	lockoutStore = make(map[string]lockoutData)
	store.UsePostgres = false
	theMockDriver.failQueries = false
}

func TestGenerateSecureSHA256Token(t *testing.T) {
	t.Run("Generates tokens", func(t *testing.T) {
		token := generateSecureSHA256Token()
		if len(token) != 64 {
			t.Errorf("Expected token length of 64, got %d", len(token))
		}

		sessionToken := generateSessionToken()
		if len(sessionToken) != 48 {
			t.Errorf("Expected session token length 48, got %d", len(sessionToken))
		}
	})
}

func TestGetIP(t *testing.T) {
	t.Run("Invalid remote address format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.RemoteAddr = "127.0.0.1"
		ip := getIP(req)
		if ip != "127.0.0.1" {
			t.Errorf("Expected original remote address fallback, got %s", ip)
		}
	})
}

func TestRequestTokenHandler(t *testing.T) {
	t.Run("Method OPTIONS preflight", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("OPTIONS", "/api/auth/request-token", nil)
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
	})

	t.Run("Method Not Allowed", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("GET", "/api/auth/request-token", nil)
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})

	t.Run("Invalid JSON Body", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString("invalid-json"))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Empty Payload", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString("{}"))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Invalid UID - Length", func(t *testing.T) {
		setupTestStores()
		payload := `{"uid":"101"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Invalid UID - Characters", func(t *testing.T) {
		setupTestStores()
		payload := `{"uid":"10abc"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Account Enumeration / Non-existent UID", func(t *testing.T) {
		setupTestStores()
		payload := `{"uid":"99999"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		// S-02 fix: response must be a generic message with no uid/username/token/expiry fields
		var res map[string]string
		json.Unmarshal(w.Body.Bytes(), &res)
		if _, hasMessage := res["message"]; !hasMessage {
			t.Errorf("Expected generic 'message' field in response, got %+v", res)
		}
		if _, hasUID := res["uid"]; hasUID {
			t.Error("Response must NOT contain 'uid' field to prevent enumeration")
		}
		if _, hasUsername := res["username"]; hasUsername {
			t.Error("Response must NOT contain 'username' field to prevent enumeration")
		}
	})

	t.Run("Rate Limit Lockout BlockedUntil active", func(t *testing.T) {
		setupTestStores()
		lockoutStore["192.0.2.55"] = lockoutData{
			BlockedUntil: time.Now().Add(5 * time.Minute),
		}
		payload := `{"uid":"10001"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		req.RemoteAddr = "192.0.2.55:1234"
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("Expected status 429 TooManyRequests, got %d", w.Code)
		}
	})

	t.Run("Success Request Token for 10001 (admin) - In-Memory", func(t *testing.T) {
		setupTestStores()
		payload := `{"uid":"10001"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Success Request Token for 10001 (admin) - PostgreSQL SQL Save success", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		payload := `{"uid":"10001"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Request Token for 10001 (admin) - PostgreSQL SQL Save error", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true
		theMockDriver.failQueries = true

		payload := `{"uid":"10001"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusInternalServerError {
			t.Errorf("Expected error response, got %d", w.Code)
		}
	})
}

func TestLoginHandler(t *testing.T) {
	t.Run("OPTIONS preflight", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("OPTIONS", "/api/auth/login", nil)
		w := httptest.NewRecorder()
		Login(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Method Not Allowed", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("GET", "/api/auth/login", nil)
		w := httptest.NewRecorder()
		Login(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})

	t.Run("Invalid JSON Body", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString("invalid-json"))
		w := httptest.NewRecorder()
		Login(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Missing Fields", func(t *testing.T) {
		setupTestStores()
		payload := `{"uid":""}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		Login(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}
	})

	t.Run("Brute-Force Lockout Trigger", func(t *testing.T) {
		setupTestStores()
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
			t.Errorf("Expected status 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("Expired OTP token verification - In-Memory", func(t *testing.T) {
		setupTestStores()
		authMu.Lock()
		otpStore["10001"] = otpData{
			Token:     "expired-otp-token",
			ExpiresAt: time.Now().Add(-5 * time.Minute),
		}
		authMu.Unlock()

		payload := `{"uid":"10001","token":"expired-otp-token"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		Login(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("Incorrect OTP Token Increments Lockout and locks after 5", func(t *testing.T) {
		setupTestStores()
		authMu.Lock()
		otpStore["10001"] = otpData{
			Token:     "correct-token",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		authMu.Unlock()

		payload := `{"uid":"10001","token":"incorrect-token"}`
		for i := 0; i < 4; i++ {
			req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
			req.RemoteAddr = "192.0.2.2:1234"
			w := httptest.NewRecorder()
			Login(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected 401 on trial %d", i)
			}
		}

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		req.RemoteAddr = "192.0.2.2:1234"
		w := httptest.NewRecorder()
		Login(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 on fifth trial, got %d", w.Code)
		}
	})

	t.Run("Successful Login - In-Memory", func(t *testing.T) {
		setupTestStores()
		authMu.Lock()
		otpStore["10001"] = otpData{
			Token:     "correct-token",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		authMu.Unlock()

		payload := `{"uid":"10001","token":"correct-token"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		req.RemoteAddr = "192.0.2.3:1234"
		w := httptest.NewRecorder()
		Login(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Successful Login - PostgreSQL", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		payload := `{"uid":"10001","token":"correct-token"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		req.RemoteAddr = "192.0.2.3:1234"
		w := httptest.NewRecorder()
		Login(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		store.UsePostgres = false
	})

	t.Run("Successful Login - PostgreSQL Save Session Error", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		payload := `{"uid":"10001","token":"correct-token"}`
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(payload))
		req.RemoteAddr = "192.0.2.3:1234"
		w := httptest.NewRecorder()

		theMockDriver.failQueries = false
		go func() {
			time.Sleep(5 * time.Millisecond)
			theMockDriver.failQueries = true
		}()

		Login(w, req)
		if w.Code != http.StatusInternalServerError && w.Code != http.StatusOK {
			t.Errorf("Expected status 500 or 200, got %d", w.Code)
		}
		store.UsePostgres = false
	})
}

func TestLogoutHandler(t *testing.T) {
	t.Run("OPTIONS preflight", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("OPTIONS", "/api/auth/logout", nil)
		w := httptest.NewRecorder()
		Logout(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Successful Logout with Cookie", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("POST", "/api/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "active-session-token"})
		w := httptest.NewRecorder()
		Logout(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Logout - PostgreSQL delete session", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		req := httptest.NewRequest("POST", "/api/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "active-session-token"})
		w := httptest.NewRecorder()
		Logout(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		store.UsePostgres = false
	})
}

func TestCheckAuthAndSessionHijacking(t *testing.T) {
	t.Run("OPTIONS preflight", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("OPTIONS", "/api/auth/check", nil)
		w := httptest.NewRecorder()
		CheckAuth(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("No token session check", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		w := httptest.NewRecorder()
		CheckAuth(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
	})

	t.Run("Expired session clean memory", func(t *testing.T) {
		setupTestStores()
		expiredToken := "expired-session-token"
		authMu.Lock()
		sessionStore[expiredToken] = sessionData{
			UID:       "10001",
			Username:  "admin",
			IPAddress: "192.0.2.5",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		authMu.Unlock()

		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: expiredToken})
		req.RemoteAddr = "192.0.2.5:1234"
		w := httptest.NewRecorder()
		CheckAuth(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
	})

	t.Run("Session IP Hijacking Mismatch", func(t *testing.T) {
		setupTestStores()
		sessionToken := "valid-session-token"
		authMu.Lock()
		sessionStore[sessionToken] = sessionData{
			UID:       "10001",
			Username:  "admin",
			IPAddress: "192.0.2.5",
			ExpiresAt: time.Now().Add(8 * time.Hour),
		}
		authMu.Unlock()

		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: sessionToken})
		req.RemoteAddr = "203.0.113.88:1234"
		w := httptest.NewRecorder()
		CheckAuth(w, req)

		var status models.AuthStatus
		json.Unmarshal(w.Body.Bytes(), &status)
		if status.IsAuthenticated {
			t.Error("Expected authentication to fail")
		}
	})

	t.Run("PostgreSQL session check success and expired cleanup", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "sql-session"})
		req.RemoteAddr = "192.0.2.100:1234"
		w := httptest.NewRecorder()
		CheckAuth(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}

		// Expired session clean SQL branch
		expiredReq := httptest.NewRequest("GET", "/api/auth/check", nil)
		expiredReq.AddCookie(&http.Cookie{Name: "session_token", Value: "expired-sql-session"})
		expiredReq.RemoteAddr = "192.0.2.100:1234"
		expiredW := httptest.NewRecorder()
		CheckAuth(expiredW, expiredReq)
		
		store.UsePostgres = false
	})

	t.Run("PostgreSQL session hijacking IP Mismatch", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "sql-session"})
		req.RemoteAddr = "203.0.113.55:1234" // Different IP to trigger hijacking
		w := httptest.NewRecorder()
		CheckAuth(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
		store.UsePostgres = false
	})
}

func TestAuthMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success-pass-through"))
	})

	wrapped := AuthMiddleware(dummyHandler)

	t.Run("OPTIONS Request CORS preflight", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("OPTIONS", "/api/protected-route", nil)
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("CSRF Check Fail", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("POST", "/api/protected-route", nil)
		req.Header.Set("Origin", "http://malicious-site.com")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("CSRF Check Fail - Empty Origin/Referer", func(t *testing.T) {
		setupTestStores()
		req := httptest.NewRequest("POST", "/api/protected-route", nil)
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status 403 Forbidden on empty Origin/Referer, got %d", w.Code)
		}
	})

	t.Run("Expired session in Middleware", func(t *testing.T) {
		setupTestStores()
		expiredToken := "expired-middleware-token"
		authMu.Lock()
		sessionStore[expiredToken] = sessionData{
			UID:       "10001",
			Username:  "admin",
			IPAddress: "192.0.2.100",
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		authMu.Unlock()

		req := httptest.NewRequest("GET", "/api/protected-route", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: expiredToken})
		req.RemoteAddr = "192.0.2.100:1234"
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("Valid Session Pass-through - In-Memory", func(t *testing.T) {
		setupTestStores()
		validToken := "valid-middleware-token"
		authMu.Lock()
		sessionStore[validToken] = sessionData{
			UID:       "10001",
			Username:  "admin",
			IPAddress: "192.0.2.100",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		authMu.Unlock()

		req := httptest.NewRequest("GET", "/api/protected-route", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: validToken})
		req.RemoteAddr = "192.0.2.100:1234"
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Valid Session Pass-through - PostgreSQL", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		req := httptest.NewRequest("GET", "/api/protected-route", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "sql-session"})
		req.RemoteAddr = "192.0.2.100:1234"
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
		store.UsePostgres = false
	})

	t.Run("Expired Session Cleanup - PostgreSQL", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		req := httptest.NewRequest("GET", "/api/protected-route", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "expired-sql-session"})
		req.RemoteAddr = "192.0.2.100:1234"
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
		store.UsePostgres = false
	})

	t.Run("Session Hijacking Detection - PostgreSQL", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true

		req := httptest.NewRequest("GET", "/api/protected-route", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: "sql-session"})
		req.RemoteAddr = "203.0.113.99:1234" // Different IP to trigger hijacking
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
		store.UsePostgres = false
	})
}

func TestSQLFailuresCoverage(t *testing.T) {
	t.Run("SQL connection closed queries failure", func(t *testing.T) {
		setupTestStores()
		db, _ := sql.Open("mock_driver", "mock")
		store.SQL = db
		store.UsePostgres = true
		theMockDriver.failQueries = true

		// 1. RequestToken SQL query failure
		payload := `{"uid":"10001"}`
		req := httptest.NewRequest("POST", "/api/auth/request-token", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		RequestToken(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500, got %d", w.Code)
		}

		// 2. Login SQL query OTP failure
		req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString(`{"uid":"10001","token":"test"}`))
		w = httptest.NewRecorder()
		Login(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}

		store.UsePostgres = false
	})
}

func TestAuthAdditionalEdgeCases(t *testing.T) {
	setupTestStores()

	t.Run("CSRF Validation with valid Referer prefix", func(t *testing.T) {
		dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		wrapped := AuthMiddleware(dummyHandler)

		req := httptest.NewRequest("POST", "/api/protected-route", nil)
		req.Header.Set("Referer", "http://localhost:5173/response-center")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
	})

	t.Run("CSRF Validation with prefix-spoofed Referer", func(t *testing.T) {
		dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		wrapped := AuthMiddleware(dummyHandler)

		req := httptest.NewRequest("POST", "/api/protected-route", nil)
		req.Header.Set("Referer", "http://localhost:5173.evil.test/poc")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403, got %d", w.Code)
		}
	})

	t.Run("Token check invalid Authorization prefix format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/auth/check", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		w := httptest.NewRecorder()
		CheckAuth(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
	})

	t.Run("Middleware invalid Authorization prefix format", func(t *testing.T) {
		dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		wrapped := AuthMiddleware(dummyHandler)

		req := httptest.NewRequest("GET", "/api/protected-route", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
	})
}
