package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
	"unicode"

	"dashboard/backend/store"
)

func NormalizeIPExpression(raw string) (string, error) {
	for _, candidate := range ipExpressionCandidates(raw) {
		if prefix, err := netip.ParsePrefix(candidate); err == nil {
			return prefix.Masked().String(), nil
		}
		if addr, err := netip.ParseAddr(candidate); err == nil {
			return addr.Unmap().String(), nil
		}
	}
	return "", fmt.Errorf("invalid IP or CIDR target: %q", raw)
}

func ipExpressionCandidates(raw string) []string {
	seen := map[string]bool{}
	var candidates []string

	add := func(value string) {
		value = strings.TrimSpace(value)
		value = strings.Trim(value, "\"'`[](){}<>,;")
		if strings.HasPrefix(strings.ToLower(value), "ip ") {
			value = strings.TrimSpace(value[3:])
		}
		if host, _, err := net.SplitHostPort(value); err == nil {
			value = host
		}
		value = strings.Trim(value, "\"'`[](){}<>,;")
		if value != "" && !seen[value] {
			seen[value] = true
			candidates = append(candidates, value)
		}
	}

	add(raw)
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return !(unicode.IsDigit(r) || unicode.IsLetter(r) || r == '.' || r == ':' || r == '/')
	}) {
		add(field)
	}

	return candidates
}

func requestIPCandidates(r *http.Request) []string {
	seen := map[string]bool{}
	var ips []string

	add := func(value string) {
		normalized, err := NormalizeIPExpression(value)
		if err == nil && !seen[normalized] {
			seen[normalized] = true
			ips = append(ips, normalized)
		}
	}

	add(r.Header.Get("X-Real-IP"))
	add(r.Header.Get("CF-Connecting-IP"))
	add(r.Header.Get("True-Client-IP"))

	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		add(part)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		add(host)
	} else {
		add(r.RemoteAddr)
	}

	return ips
}

func requestClientIP(r *http.Request) string {
	candidates := requestIPCandidates(r)
	if len(candidates) > 0 {
		return candidates[0]
	}
	return r.RemoteAddr
}

func requestHasBannedIP(r *http.Request) (bool, string, error) {
	for _, ip := range requestIPCandidates(r) {
		banned, err := store.IsIPBanned(ip)
		if err != nil {
			return false, "", err
		}
		if banned {
			return true, ip, nil
		}
	}
	return false, "", nil
}

func IPBanMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		banned, ip, err := requestHasBannedIP(r)
		if err != nil {
			log.Printf("[IP BAN] Failed to evaluate request IP ban status: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "IP ban enforcement unavailable"})
			return
		}
		if banned {
			log.Printf("[IP BAN] Blocked dashboard request from banned IP %s", ip)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden: your IP is banned"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func HandleInternalIPBanCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	banned, ip, err := requestHasBannedIP(r)
	if err != nil {
		log.Printf("[IP BAN] Gateway check failed closed: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if banned {
		log.Printf("[IP BAN] Gateway blocked request from banned IP %s", ip)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func syncBankBannedIP(ipAddress string, actor string, status string, reason string) error {
	bankURL := os.Getenv("BANK_BACKEND_URL")
	if bankURL == "" {
		return nil
	}
	syncToken := os.Getenv("AEGIS_INTERNAL_TOKEN")
	if syncToken == "" {
		return fmt.Errorf("AEGIS_INTERNAL_TOKEN is empty")
	}

	body, err := json.Marshal(map[string]string{
		"ipAddress": ipAddress,
		"bannedBy":  actor,
		"status":    status,
		"reason":    reason,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(bankURL, "/")+"/api/admin/security/banned-ips", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Token", syncToken)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bank backend returned status %d", resp.StatusCode)
	}
	return nil
}
