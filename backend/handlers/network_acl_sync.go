package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	defaultNetworkACLRuleStart = int32(2000)
	defaultNetworkACLRuleLimit = int32(200)
)

func syncNetworkBannedIP(rawIP string, status string) error {
	networkACLID := strings.TrimSpace(os.Getenv("AWS_NETWORK_ACL_ID"))
	if networkACLID == "" {
		return nil
	}

	cidr, err := normalizeWAFIP(rawIP)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	if !prefix.Addr().Is4() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "ap-southeast-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("network ACL config load failed: %w", err)
	}
	client := ec2.NewFromConfig(cfg)

	entries, err := describeNetworkACLEntries(ctx, client, networkACLID)
	if err != nil {
		return err
	}

	if strings.EqualFold(status, "unbanned") {
		return deleteNetworkACLEntries(ctx, client, networkACLID, entries, cidr)
	}
	return createNetworkACLEntries(ctx, client, networkACLID, entries, cidr)
}

func describeNetworkACLEntries(ctx context.Context, client *ec2.Client, networkACLID string) ([]ec2types.NetworkAclEntry, error) {
	out, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
		NetworkAclIds: []string{networkACLID},
	})
	if err != nil {
		return nil, fmt.Errorf("network ACL describe failed: %w", err)
	}
	if len(out.NetworkAcls) == 0 {
		return nil, fmt.Errorf("network ACL %s not found", networkACLID)
	}
	return out.NetworkAcls[0].Entries, nil
}

func createNetworkACLEntries(ctx context.Context, client *ec2.Client, networkACLID string, entries []ec2types.NetworkAclEntry, cidr string) error {
	ruleNumber, err := networkACLRuleNumber(entries, cidr)
	if err != nil {
		return err
	}

	var failures []string
	if !networkACLEntryExists(entries, cidr, false) {
		if err := createNetworkACLEntry(ctx, client, networkACLID, cidr, ruleNumber, false); err != nil {
			failures = append(failures, fmt.Sprintf("ingress: %v", err))
		}
	}
	if !networkACLEntryExists(entries, cidr, true) {
		if err := createNetworkACLEntry(ctx, client, networkACLID, cidr, ruleNumber, true); err != nil {
			failures = append(failures, fmt.Sprintf("egress: %v", err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func createNetworkACLEntry(ctx context.Context, client *ec2.Client, networkACLID string, cidr string, ruleNumber int32, egress bool) error {
	_, err := client.CreateNetworkAclEntry(ctx, &ec2.CreateNetworkAclEntryInput{
		NetworkAclId: aws.String(networkACLID),
		RuleNumber:   aws.Int32(ruleNumber),
		Protocol:     aws.String("-1"),
		RuleAction:   ec2types.RuleActionDeny,
		Egress:       aws.Bool(egress),
		CidrBlock:    aws.String(cidr),
		PortRange: &ec2types.PortRange{
			From: aws.Int32(0),
			To:   aws.Int32(0),
		},
	})
	if err != nil {
		return fmt.Errorf("create rule %d for %s failed: %w", ruleNumber, cidr, err)
	}
	return nil
}

func deleteNetworkACLEntries(ctx context.Context, client *ec2.Client, networkACLID string, entries []ec2types.NetworkAclEntry, cidr string) error {
	var failures []string
	for _, entry := range entries {
		if !isRuntimeNetworkACLEntry(entry, cidr) {
			continue
		}
		if entry.RuleNumber == nil || entry.Egress == nil {
			continue
		}
		_, err := client.DeleteNetworkAclEntry(ctx, &ec2.DeleteNetworkAclEntryInput{
			NetworkAclId: aws.String(networkACLID),
			RuleNumber:   entry.RuleNumber,
			Egress:       entry.Egress,
		})
		if err != nil {
			failures = append(failures, fmt.Sprintf("delete rule %d failed: %v", aws.ToInt32(entry.RuleNumber), err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func networkACLRuleNumber(entries []ec2types.NetworkAclEntry, cidr string) (int32, error) {
	start, limit := networkACLRuntimeRange()
	for _, entry := range entries {
		if isRuntimeNetworkACLEntry(entry, cidr) && entry.RuleNumber != nil {
			return aws.ToInt32(entry.RuleNumber), nil
		}
	}

	used := map[int32]bool{}
	for _, entry := range entries {
		if entry.RuleNumber == nil {
			continue
		}
		ruleNumber := aws.ToInt32(entry.RuleNumber)
		if ruleNumber >= start && ruleNumber < start+limit {
			used[ruleNumber] = true
		}
	}
	for ruleNumber := start; ruleNumber < start+limit; ruleNumber++ {
		if !used[ruleNumber] {
			return ruleNumber, nil
		}
	}
	return 0, fmt.Errorf("network ACL runtime rule range %d-%d exhausted", start, start+limit-1)
}

func networkACLEntryExists(entries []ec2types.NetworkAclEntry, cidr string, egress bool) bool {
	for _, entry := range entries {
		if !isRuntimeNetworkACLEntry(entry, cidr) || entry.Egress == nil {
			continue
		}
		if aws.ToBool(entry.Egress) == egress {
			return true
		}
	}
	return false
}

func isRuntimeNetworkACLEntry(entry ec2types.NetworkAclEntry, cidr string) bool {
	if entry.CidrBlock == nil || aws.ToString(entry.CidrBlock) != cidr {
		return false
	}
	if entry.RuleNumber == nil {
		return false
	}
	start, limit := networkACLRuntimeRange()
	ruleNumber := aws.ToInt32(entry.RuleNumber)
	return ruleNumber >= start && ruleNumber < start+limit && entry.RuleAction == ec2types.RuleActionDeny
}

func networkACLRuntimeRange() (int32, int32) {
	start := parseInt32Env("AWS_NETWORK_ACL_RULE_START", defaultNetworkACLRuleStart)
	limit := parseInt32Env("AWS_NETWORK_ACL_RULE_LIMIT", defaultNetworkACLRuleLimit)
	if start < 1 || start > 32000 {
		start = defaultNetworkACLRuleStart
	}
	if limit < 1 || start+limit > 32766 {
		limit = defaultNetworkACLRuleLimit
	}
	return start, limit
}

func parseInt32Env(name string, fallback int32) int32 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return fallback
	}
	return int32(value)
}
