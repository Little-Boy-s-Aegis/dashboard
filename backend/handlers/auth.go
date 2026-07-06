package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"dashboard/backend/models"
	"dashboard/backend/store"
)

// Allowed 5-digit UIDs mapped to their Operator display names/usernames (Fallback mode)
var allowedUIDs = map[string]string{
	"10001": "admin",
	"10002": "sarah",
	"10003": "alex",
}

type otpData struct {
	Token     string
	ExpiresAt time.Time
}

type sessionData struct {
	UID       string
	Username  string
	IPAddress string
	ExpiresAt time.Time
}

type lockoutData struct {
	FailedAttempts int
	BlockedUntil   time.Time
}

var (
	otpStore     = make(map[string]otpData)
	sessionStore = make(map[string]sessionData)
	lockoutStore = make(map[string]lockoutData)
	authMu       sync.RWMutex
)

// Helper: Generate secure 100% random SHA-256 token
func generateSecureSHA256Token() string {
	b := make([]byte, 32)
	rand.Read(b)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// Helper: Generate secure random session token
func generateSessionToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Helper: Get remote IP address
func getIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// POST /api/auth/request-token
func RequestToken(w http.ResponseWriter, r *http.Request) {
	// Enable CORS headers for preflight and standard requests
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var req models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	uid := strings.TrimSpace(req.UID)
	if uid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Operator UID is required"})
		return
	}

	// Pentest validation: Ensure UID is exactly 5 digits to prevent SQL injection or bad inputs
	if len(uid) != 5 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Operator UID must be exactly 5 digits"})
		return
	}
	for _, c := range uid {
		if c < '0' || c > '9' {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Operator UID must contain only numbers"})
			return
		}
	}

	ip := getIP(r)

	authMu.Lock()
	defer authMu.Unlock()

	// 1. Rate limit / Lockout check for token generation
	if data, exists := lockoutStore[ip]; exists && time.Now().Before(data.BlockedUntil) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "Too many requests. Please try again after " + data.BlockedUntil.Sub(time.Now()).Round(time.Second).String(),
		})
		return
	}

	// 2. Account enumeration mitigation & UID lookup
	var username string
	var isAllowed bool
	if store.UsePostgres {
		err := store.SQL.QueryRow("SELECT username FROM operators WHERE uid = $1", uid).Scan(&username)
		isAllowed = (err == nil)
	} else {
		username, isAllowed = allowedUIDs[uid]
	}

	if !isAllowed {
		// Mock delay to prevent timing attacks / account enumeration
		time.Sleep(100 * time.Millisecond)
		// Return generic error message to prevent account harvesting
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid login request or account disabled"})
		return
	}

	// 3. Generate token
	token := generateSecureSHA256Token()
	expiry := time.Now().Add(5 * time.Minute)

	// Save token in memory store or SQL
	if store.UsePostgres {
		if err := store.SaveSQLOTP(uid, token, expiry); err != nil {
			log.Printf("[DATABASE ERROR] Failed to save OTP in Postgres: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database write error"})
			return
		}
	} else {
		otpStore[uid] = otpData{
			Token:     token,
			ExpiresAt: expiry,
		}
	}

	fmt.Printf("\n🔑 [SECURITY AUTH OTP] Copy this SHA-256 token to login for UID %s (%s):\n--> %s\n\n", uid, username, token)

	// Send back response
	writeJSON(w, http.StatusOK, models.AuthResponse{
		UID:      uid,
		Username: username,
		Token:    token,
		Expiry:   expiry,
	})
}

// POST /api/auth/login
func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	uid := strings.TrimSpace(req.UID)
	token := strings.TrimSpace(req.Token)
	ip := getIP(r)

	if uid == "" || token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "UID and token are required"})
		return
	}

	authMu.Lock()
	defer authMu.Unlock()

	// 1. Lockout check
	lockKey := uid + "@" + ip
	if data, exists := lockoutStore[lockKey]; exists && time.Now().Before(data.BlockedUntil) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "Account is temporarily locked due to too many failed attempts. Locked until " + data.BlockedUntil.Format("15:04:05"),
		})
		return
	}

	// 2. Validate token
	var tokenMatch bool
	var otpExpired bool
	if store.UsePostgres {
		dbToken, dbExpiry, err := store.GetSQLOTP(uid)
		if err == nil {
			tokenMatch = (dbToken == token)
			otpExpired = time.Now().After(dbExpiry)
		}
	} else {
		otp, exists := otpStore[uid]
		if exists {
			tokenMatch = (otp.Token == token)
			otpExpired = time.Now().After(otp.ExpiresAt)
		}
	}

	if !tokenMatch || otpExpired {
		// Increment failed attempts
		lockData := lockoutStore[lockKey]
		lockData.FailedAttempts++
		if lockData.FailedAttempts >= 5 {
			lockData.BlockedUntil = time.Now().Add(15 * time.Minute)
			lockoutStore[lockKey] = lockData
			log.Printf("[SECURITY ALERT] Lockout triggered for UID: %s at IP: %s (5 failed attempts)", uid, ip)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "Too many failed attempts. This account has been locked for 15 minutes.",
			})
			return
		}
		lockoutStore[lockKey] = lockData

		// Delay response to prevent brute forcing
		time.Sleep(300 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials or token expired"})
		return
	}

	// 3. SUCCESSFUL LOGIN -> Consume token immediately (one-time use)
	if store.UsePostgres {
		store.DeleteSQLOTP(uid)
	} else {
		delete(otpStore, uid)
	}
	delete(lockoutStore, lockKey) // reset lockout counter

	// Mapped Username
	var username string
	if store.UsePostgres {
		store.SQL.QueryRow("SELECT username FROM operators WHERE uid = $1", uid).Scan(&username)
	} else {
		username = allowedUIDs[uid]
	}

	// 4. Create Session
	sessionToken := generateSessionToken()
	// Set expiration to exactly 8 hours from now
	expiresAt := time.Now().Add(8 * time.Hour)

	if store.UsePostgres {
		if err := store.SaveSQLSession(sessionToken, uid, username, ip, expiresAt); err != nil {
			log.Printf("[DATABASE ERROR] Failed to save session in Postgres: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database write error"})
			return
		}
	} else {
		sessionStore[sessionToken] = sessionData{
			UID:       uid,
			Username:  username,
			IPAddress: ip,
			ExpiresAt: expiresAt,
		}
	}

	log.Printf("[SECURITY AUTH] Successful login for UID: %s (%s) from IP: %s. Session active for 8 hours.", uid, username, ip)

	// Set HttpOnly, Secure, SameSite secure cookie for session token
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   false, // Set to true in prod (HTTPS)
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Return json response for flexibility
	writeJSON(w, http.StatusOK, models.LoginResponse{
		UID:          uid,
		Username:     username,
		SessionToken: sessionToken,
		ExpiresAt:    expiresAt,
	})
}

// POST /api/auth/logout
func Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	cookie, err := r.Cookie("session_token")
	var sessionToken string
	if err == nil {
		sessionToken = cookie.Value
	} else {
		// Fallback to auth header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			sessionToken = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	authMu.Lock()
	if sessionToken != "" {
		if store.UsePostgres {
			store.DeleteSQLSession(sessionToken)
		} else {
			delete(sessionStore, sessionToken)
		}
		log.Printf("[SECURITY AUTH] Session invalidated successfully.")
	}
	authMu.Unlock()

	// Clear cookie
	clearCookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, clearCookie)

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// GET /api/auth/check
func CheckAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	cookie, err := r.Cookie("session_token")
	var sessionToken string
	if err == nil {
		sessionToken = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			sessionToken = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	var sessionUID string
	var sessionUsername string
	var sessionIP string
	var sessionExpiresAt time.Time
	var sessionExists bool

	if store.UsePostgres {
		dbUid, dbUsername, dbIp, dbExpiresAt, err := store.GetSQLSession(sessionToken)
		if err == nil {
			sessionUID = dbUid
			sessionUsername = dbUsername
			sessionIP = dbIp
			sessionExpiresAt = dbExpiresAt
			sessionExists = true
		}
	} else {
		authMu.RLock()
		session, exists := sessionStore[sessionToken]
		if exists {
			sessionUID = session.UID
			sessionUsername = session.Username
			sessionIP = session.IPAddress
			sessionExpiresAt = session.ExpiresAt
			sessionExists = true
		}
		authMu.RUnlock()
	}

	// 1. IP Binding Validation (Anti-Session Hijacking)
	ip := getIP(r)
	if sessionExists && sessionIP != ip {
		log.Printf("[SECURITY ALERT] Session IP mismatch detected on CheckAuth! Revoking session. Session IP: %s, Request IP: %s", sessionIP, ip)
		authMu.Lock()
		if store.UsePostgres {
			store.DeleteSQLSession(sessionToken)
		} else {
			delete(sessionStore, sessionToken)
		}
		authMu.Unlock()
		sessionExists = false
	}

	if !sessionExists || time.Now().After(sessionExpiresAt) {
		if sessionExists && time.Now().After(sessionExpiresAt) {
			// Clean expired session
			authMu.Lock()
			if store.UsePostgres {
				store.DeleteSQLSession(sessionToken)
			} else {
				delete(sessionStore, sessionToken)
			}
			authMu.Unlock()
		}
		writeJSON(w, http.StatusOK, models.AuthStatus{IsAuthenticated: false, Username: "", UID: ""})
		return
	}

	writeJSON(w, http.StatusOK, models.AuthStatus{
		IsAuthenticated: true,
		Username:        sessionUsername,
		UID:             sessionUID,
		ExpiresAt:       sessionExpiresAt,
	})
}

// AuthMiddleware: checks session validity before accessing protected APIs
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Anti-Pentesting HTTP Security Headers (Injected to all API responses)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")

		// Bypass auth for login endpoints
		if r.URL.Path == "/api/auth/request-token" || r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/check" || r.URL.Path == "/api/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// Service-to-service auth bypass using internal key
		internalToken := os.Getenv("AEGIS_INTERNAL_TOKEN")
		if internalToken == "" {
			internalToken = "aegis-secret-security-sync-token-2026"
		}
		if r.Header.Get("X-Aegis-Internal-Key") == internalToken {
			next.ServeHTTP(w, r)
			return
		}

		// CSRF & Host validation for modifying requests (POST, PUT, DELETE)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")
			
			isValidOrigin := origin == "http://localhost:5173" || strings.HasPrefix(referer, "http://localhost:5173")
			if origin == "" && referer == "" {
				isValidOrigin = true // allow if both empty (e.g. same origin direct request)
			}

			if !isValidOrigin {
				log.Printf("[SECURITY ALERT] CSRF or forbidden origin request blocked! Origin: %s, Referer: %s", origin, referer)
				w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden: Request origin is invalid"})
				return
			}
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusOK)
			return
		}

		cookie, err := r.Cookie("session_token")
		var sessionToken string
		if err == nil {
			sessionToken = cookie.Value
		} else {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				sessionToken = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		var sessionExpiresAt time.Time
		var sessionIP string
		var sessionExists bool

		if store.UsePostgres {
			_, _, dbIp, dbExpiresAt, err := store.GetSQLSession(sessionToken)
			if err == nil {
				sessionExpiresAt = dbExpiresAt
				sessionIP = dbIp
				sessionExists = true
			}
		} else {
			authMu.RLock()
			session, exists := sessionStore[sessionToken]
			if exists {
				sessionExpiresAt = session.ExpiresAt
				sessionIP = session.IPAddress
				sessionExists = true
			}
			authMu.RUnlock()
		}

		// 2. IP Binding Validation (Anti-Hijacking)
		ip := getIP(r)
		if sessionExists && sessionIP != ip {
			log.Printf("[SECURITY ALERT] Session hijacking detected! Session IP: %s, Request IP: %s. Revoking session.", sessionIP, ip)
			authMu.Lock()
			if store.UsePostgres {
				store.DeleteSQLSession(sessionToken)
			} else {
				delete(sessionStore, sessionToken)
			}
			authMu.Unlock()
			sessionExists = false
		}

		if !sessionExists || time.Now().After(sessionExpiresAt) {
			if sessionExists && time.Now().After(sessionExpiresAt) {
				authMu.Lock()
				if store.UsePostgres {
					store.DeleteSQLSession(sessionToken)
				} else {
					delete(sessionStore, sessionToken)
				}
				authMu.Unlock()
			}
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized: Session invalid or expired"})
			return
		}

		next.ServeHTTP(w, r)
	})
}
