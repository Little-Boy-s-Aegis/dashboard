package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// wafIPListCache caches the WAF IP list to avoid 2 AWS API calls per dashboard poll.
// TTL = 30 seconds (WAF changes are rare; freshness tolerance is high).
var wafIPListCache struct {
	mu          sync.RWMutex
	ips         []string
	lastRefresh time.Time
	ttl         time.Duration
}

func init() {
	wafIPListCache.ttl = 30 * time.Second
}

// InvalidateWAFIPListCache forces the next listWAFBannedIPs call to re-query AWS.
func InvalidateWAFIPListCache() {
	wafIPListCache.mu.Lock()
	wafIPListCache.lastRefresh = time.Time{}
	wafIPListCache.mu.Unlock()
}

type wafIPSetTarget struct {
	name   string
	id     string
	scope  types.Scope
	region string
}

func syncWAFBannedIP(rawIP string, status string) error {
	targets := wafIPSetTargets()
	if len(targets) == 0 {
		return nil
	}

	cidr, err := normalizeWAFIP(rawIP)
	if err != nil {
		return err
	}

	var failures []string
	for _, target := range targets {
		if err := updateWAFIPSet(target, cidr, strings.EqualFold(status, "unbanned")); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	InvalidateWAFIPListCache() // WAF changed, refresh cache on next read
	return nil
}

// listWAFBannedIPs returns cached WAF IPs, refreshing from AWS every 30 seconds.
func listWAFBannedIPs() ([]string, error) {
	wafIPListCache.mu.RLock()
	if time.Since(wafIPListCache.lastRefresh) < wafIPListCache.ttl {
		result := wafIPListCache.ips
		wafIPListCache.mu.RUnlock()
		return result, nil
	}
	wafIPListCache.mu.RUnlock()

	// Cache miss — refresh
	wafIPListCache.mu.Lock()
	defer wafIPListCache.mu.Unlock()

	// Double-check after write lock
	if time.Since(wafIPListCache.lastRefresh) < wafIPListCache.ttl {
		return wafIPListCache.ips, nil
	}

	ips, err := listWAFBannedIPsUncached()
	if err != nil {
		log.Printf("[WAF CACHE] Failed to refresh WAF IP list: %v", err)
		// Return stale cache if available
		if wafIPListCache.ips != nil {
			return wafIPListCache.ips, nil
		}
		return nil, err
	}
	wafIPListCache.ips = ips
	wafIPListCache.lastRefresh = time.Now()
	return ips, nil
}

func listWAFBannedIPsUncached() ([]string, error) {
	targets := wafIPSetTargets()
	if len(targets) == 0 {
		return nil, nil
	}

	seen := map[string]bool{}
	var addresses []string
	var failures []string

	for _, target := range targets {
		current, err := getWAFIPSetAddresses(target)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		for _, cidr := range current {
			display := displayWAFIP(cidr)
			if display != "" && !seen[display] {
				seen[display] = true
				addresses = append(addresses, display)
			}
		}
	}

	if len(failures) > 0 && len(addresses) == 0 {
		return nil, errors.New(strings.Join(failures, "; "))
	}
	return addresses, nil
}

func wafIPSetTargets() []wafIPSetTarget {
	var targets []wafIPSetTarget

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "ap-southeast-1"
	}
	if name, id := os.Getenv("AWS_WAF_IP_SET_NAME"), os.Getenv("AWS_WAF_IP_SET_ID"); name != "" && id != "" {
		targets = append(targets, wafIPSetTarget{
			name:   name,
			id:     id,
			scope:  types.ScopeRegional,
			region: region,
		})
	}

	if name, id := os.Getenv("AWS_WAF_CLOUDFRONT_IP_SET_NAME"), os.Getenv("AWS_WAF_CLOUDFRONT_IP_SET_ID"); name != "" && id != "" {
		targets = append(targets, wafIPSetTarget{
			name:   name,
			id:     id,
			scope:  types.ScopeCloudfront,
			region: "us-east-1",
		})
	}

	return targets
}

func normalizeWAFIP(rawIP string) (string, error) {
	normalized, err := NormalizeIPExpression(rawIP)
	if err != nil {
		return "", err
	}
	if strings.Contains(normalized, "/") {
		prefix, err := netip.ParsePrefix(normalized)
		if err != nil {
			return "", err
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(normalized)
	if err != nil {
		return "", err
	}
	if addr.Is4() {
		return addr.String() + "/32", nil
	}
	return addr.String() + "/128", nil
}

func getWAFIPSetAddresses(target wafIPSetTarget) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(target.region))
	if err != nil {
		return nil, fmt.Errorf("%s/%s config load failed: %w", target.scope, target.name, err)
	}
	client := wafv2.NewFromConfig(cfg)

	current, err := client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Name:  aws.String(target.name),
		Id:    aws.String(target.id),
		Scope: target.scope,
	})
	if err != nil {
		return nil, fmt.Errorf("%s/%s get failed: %w", target.scope, target.name, err)
	}
	return append([]string{}, current.IPSet.Addresses...), nil
}

func displayWAFIP(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return strings.TrimSpace(cidr)
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	if (addr.Is4() && prefix.Bits() == 32) || (addr.Is6() && prefix.Bits() == 128) {
		return addr.String()
	}
	return prefix.String()
}

func updateWAFIPSet(target wafIPSetTarget, cidr string, remove bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(target.region))
	if err != nil {
		return fmt.Errorf("%s/%s config load failed: %w", target.scope, target.name, err)
	}
	client := wafv2.NewFromConfig(cfg)

	current, err := client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Name:  aws.String(target.name),
		Id:    aws.String(target.id),
		Scope: target.scope,
	})
	if err != nil {
		return fmt.Errorf("%s/%s get failed: %w", target.scope, target.name, err)
	}

	addresses := append([]string{}, current.IPSet.Addresses...)
	foundAt := -1
	for idx, address := range addresses {
		if address == cidr {
			foundAt = idx
			break
		}
	}

	if remove {
		if foundAt == -1 {
			return nil
		}
		addresses = append(addresses[:foundAt], addresses[foundAt+1:]...)
	} else if foundAt == -1 {
		addresses = append(addresses, cidr)
	} else {
		return nil
	}

	_, err = client.UpdateIPSet(ctx, &wafv2.UpdateIPSetInput{
		Name:      aws.String(target.name),
		Id:        aws.String(target.id),
		Scope:     target.scope,
		Addresses: addresses,
		LockToken: current.LockToken,
	})
	if err != nil {
		return fmt.Errorf("%s/%s update failed: %w", target.scope, target.name, err)
	}
	return nil
}
