package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	hostname := u.Hostname()
	if hostname == "localhost" || hostname == "127.0.0.1" {
		return true
	}
	if hostname == "d1y2tczt9tmz2d.cloudfront.net" {
		return true
	}
	if hostname == "littleboys.biz" || hostname == "www.littleboys.biz" || hostname == "soc.littleboys.biz" {
		return true
	}
	if strings.HasSuffix(hostname, ".littleboys.biz") {
		return true
	}
	fe := os.Getenv("FRONTEND_URL")
	if fe != "" {
		if feU, err := url.Parse(fe); err == nil {
			if hostname == feU.Hostname() {
				return true
			}
		}
	}
	return false
}

func getAllowedOrigin(r *http.Request) string {
	origin := r.Header.Get("Origin")
	if origin != "" && isAllowedOrigin(origin) {
		return origin
	}
	referer := r.Header.Get("Referer")
	if referer != "" {
		if u, err := url.Parse(referer); err == nil {
			refOrigin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
			if isAllowedOrigin(refOrigin) {
				return refOrigin
			}
		}
	}
	defaultOrigin := os.Getenv("FRONTEND_URL")
	if defaultOrigin == "" {
		return "http://localhost:5173"
	}
	return defaultOrigin
}

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

func secureCookieForRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	override := strings.ToLower(strings.TrimSpace(os.Getenv("AEGIS_COOKIE_SECURE")))
	if override == "true" {
		return true
	}
	if override == "false" {
		return false
	}
	if isLoopbackRequest(r) {
		return false
	}
	if r.TLS != nil {
		return true
	}
	forwardedProto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
	if forwardedProto == "https" {
		return true
	}
	return false
}

func isLoopbackRequest(r *http.Request) bool {
	return isLoopbackHost(r.Host) || isLoopbackHost(r.RemoteAddr)
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Helper: Get remote IP address
func getIP(r *http.Request) string {
	return requestClientIP(r)
}

// Helper: Check if brute force vulnerability is enabled in the Java Bank Backend
func isBruteForceVulnerable() bool {
	client := &http.Client{Timeout: 1 * time.Second}
	bankURL := os.Getenv("BANK_BACKEND_URL")
	if bankURL == "" {
		bankURL = "http://be-backend:8080"
	}
	req, err := http.NewRequest("GET", bankURL+"/api/admin/security/status", nil)
	if err != nil {
		return false
	}
	syncToken := os.Getenv("AEGIS_INTERNAL_TOKEN")
	if syncToken != "" {
		req.Header.Set("X-Aegis-Token", syncToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var status struct {
		BruteForceEnabled bool `json:"bruteForceEnabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return false
	}
	return status.BruteForceEnabled
}

// POST /api/auth/request-token
func RequestToken(w http.ResponseWriter, r *http.Request) {
	// Enable CORS headers for preflight and standard requests
	w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
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
		if err != nil {
			if err == sql.ErrNoRows {
				isAllowed = false
			} else {
				log.Printf("[DATABASE ERROR] Failed to query operator: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database read error"})
				return
			}
		} else {
			isAllowed = true
		}
	} else {
		username, isAllowed = allowedUIDs[uid]
	}

	// 3. Generate token
	token := generateSecureSHA256Token()
	expiry := time.Now().Add(5 * time.Minute)

	// Check if vulnerable to brute force / account enumeration
	isVulnerable := isBruteForceVulnerable()

	if isAllowed {
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
		// Write to a temporary file outside the workspace to prevent repo tracking
		otpMsg := fmt.Sprintf("[SECURITY AUTH OTP] Copy this SHA-256 token to login for UID %s (%s):\n--> %s\n", uid, username, token)
		_ = os.WriteFile(filepath.Join(os.TempDir(), "otp.txt"), []byte(otpMsg), 0600)
		log.Printf("[SECURITY AUTH OTP] Copy this SHA-256 token to login for UID %s (%s): %s", uid, username, token)
		log.Printf("[SECURITY AUTH] One-time password generated for authentication request.")

		if isVulnerable {
			// Vulnerable mode: expose real username but do NOT leak token in response
			writeJSON(w, http.StatusOK, models.AuthResponse{
				UID:      uid,
				Username: username,
				Token:    "",
				Expiry:   expiry,
			})
			return
		}
	} else {
		if isVulnerable {
			// Vulnerable mode: return error response for invalid UID
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Operator not found"})
			return
		}
		// Mock delay to prevent timing attacks / account enumeration
		time.Sleep(50 * time.Millisecond)
	}

	// Send back a generic acknowledgment — identical for both valid and invalid UIDs
	// to prevent account enumeration. No uid/username/token/expiry fields are exposed.
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "If the UID is valid, a one-time password has been generated. Check the secure OTP channel.",
	})
}

// GET /api/internal/otp/latest — Fast OTP retrieval (bypasses CloudWatch)
// Authenticated with X-Aegis-Internal-Key header.
// Returns the latest OTP token directly from the local otp.txt file on the container.
func GetLatestOTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	// Verify internal secret key
	internalToken := os.Getenv("AEGIS_INTERNAL_TOKEN")
	if internalToken == "" || r.Header.Get("X-Aegis-Internal-Key") != internalToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	// Read the otp.txt file directly from temporary directory
	data, err := os.ReadFile(filepath.Join(os.TempDir(), "otp.txt"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":   "No OTP token available. Request a token first via /api/auth/request-token",
			"details": err.Error(),
		})
		return
	}

	content := strings.TrimSpace(string(data))

	// Extract the token from the otp.txt format:
	// [SECURITY AUTH OTP] Copy this SHA-256 token to login for UID XXXXX (username):
	// --> <token>
	lines := strings.Split(content, "\n")
	var token string
	var info string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-->") {
			token = strings.TrimSpace(strings.TrimPrefix(line, "-->"))
		} else if strings.HasPrefix(line, "[SECURITY AUTH OTP]") {
			info = line
		}
	}

	if token == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Could not parse OTP token from otp.txt",
			"raw":   content,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token": token,
		"info":  info,
	})
}

// POST /api/auth/login
func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
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
		w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
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

	// 3. SUCCESSFUL LOGIN -> Consume and delete all tokens immediately
	if store.UsePostgres {
		store.DeleteAllSQLOTPs()
	} else {
		for k := range otpStore {
			delete(otpStore, k)
		}
	}
	delete(lockoutStore, lockKey)                         // reset lockout counter
	_ = os.Remove(filepath.Join(os.TempDir(), "otp.txt")) // Delete OTP retrieval file after successful consumption

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

	// Keep Secure cookies in HTTPS/proxy deployments, but allow local HTTP dev
	// at 127.0.0.1/localhost so the browser can send the session cookie.
	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   secureCookieForRequest(r),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Return json response for flexibility
	writeJSON(w, http.StatusOK, models.LoginResponse{
		UID:          uid,
		Username:     username,
		SessionToken: "", // Redacted: Session token is only sent via HttpOnly cookie
		ExpiresAt:    expiresAt,
	})
}

// POST /api/auth/logout
func Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
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
		Secure:   secureCookieForRequest(r),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, clearCookie)

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// GET /api/auth/check
func CheckAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
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
	if sessionExists && sessionIP != ip && !isPrivateIP(ip) && !isPrivateIP(sessionIP) {
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

		// Bypass auth for health check and login endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/api/internal/ip-ban/check" || r.URL.Path == "/api/auth/request-token" || r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/check" || r.URL.Path == "/api/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// Service-to-service auth bypass using internal key (I-01 fix: no hardcoded fallback)
		internalToken := os.Getenv("AEGIS_INTERNAL_TOKEN")
		if internalToken != "" && r.Header.Get("X-Aegis-Internal-Key") == internalToken {
			next.ServeHTTP(w, r)
			return
		}

		// CSRF & Host validation for modifying requests (POST, PUT, DELETE)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")

			allowedOrigin := getAllowedOrigin(r)
			isValidOrigin := origin == allowedOrigin
			if !isValidOrigin {
				allowedHosts := map[string]bool{
					"littleboys.biz":                true,
					"www.littleboys.biz":            true,
					"soc.littleboys.biz":            true,
					"d1y2tczt9tmz2d.cloudfront.net": true,
				}
				if origin != "" {
					if parsed, err := url.Parse(origin); err == nil {
						if allowedHosts[parsed.Hostname()] || strings.HasSuffix(parsed.Hostname(), ".littleboys.biz") {
							isValidOrigin = true
						}
					}
				}
				if !isValidOrigin && referer != "" {
					if parsed, err := url.Parse(referer); err == nil {
						if allowedHosts[parsed.Hostname()] || strings.HasSuffix(parsed.Hostname(), ".littleboys.biz") {
							isValidOrigin = true
						}
					}
				}
			}
			if !isValidOrigin && referer != "" {
				if parsedUrl, err := url.Parse(referer); err == nil {
					if u, err2 := url.Parse(allowedOrigin); err2 == nil {
						if parsedUrl.Host == u.Host {
							isValidOrigin = true
						}
					}
				}
			}

			if !isValidOrigin {
				log.Printf("[SECURITY ALERT] CSRF or forbidden origin request blocked! Origin: %s, Referer: %s", origin, referer)
				w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden: Request origin is invalid"})
				return
			}
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
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

		// 2. IP Binding Validation (Anti-Hijacking) - Bypassed for private/VPC network interface compatibility (ALB/CloudFront)
		ip := getIP(r)
		if sessionExists && sessionIP != ip && !isPrivateIP(ip) && !isPrivateIP(sessionIP) {
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
			w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized: Session invalid or expired"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper: check if IP belongs to private network ranges
func isPrivateIP(ipStr string) bool {
	ipStr = strings.Trim(ipStr, "[]")
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ipStr = strings.Trim(ipStr, "[]")
	if ipStr == "localhost" || ipStr == "127.0.0.1" || ipStr == "::1" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	ipv4 := ip.To4()
	if ipv4 != nil {
		return ipv4[0] == 10 ||
			(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
			(ipv4[0] == 192 && ipv4[1] == 168) ||
			(ipv4[0] == 127)
	}
	return false
}

// GET /api/operators
func GetOperators(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", getAllowedOrigin(r))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	type OperatorInfo struct {
		UID      string `json:"uid"`
		Username string `json:"username"`
	}

	operators := []OperatorInfo{}

	if store.UsePostgres {
		rows, err := store.SQL.Query("SELECT uid, username FROM operators ORDER BY uid ASC")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var op OperatorInfo
				if err := rows.Scan(&op.UID, &op.Username); err == nil {
					operators = append(operators, op)
				}
			}
		} else {
			log.Printf("[DATABASE ERROR] GetOperators failed: %v", err)
		}
	} else {
		// Fallback memory list
		operators = []OperatorInfo{
			{UID: "10001", Username: "admin"},
			{UID: "10002", Username: "sarah"},
			{UID: "10003", Username: "alex"},
		}
	}

	// Also add "AI Copilot" as a virtual operator option!
	operators = append(operators, OperatorInfo{UID: "99999", Username: "AI Copilot"})

	writeJSON(w, http.StatusOK, operators)
}
