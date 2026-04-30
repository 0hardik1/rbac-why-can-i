package cani

import (
	"fmt"
	"strings"
)

// matchesAssumedRole reports whether assumedRoleArn is the STS assumed-role
// form of roleArn (with or without a session suffix).
//
//	roleArn:        arn:aws:iam::ACCOUNT:role/[PATH/]ROLE-NAME
//	assumedRoleArn: arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME[/SESSION-NAME]
func matchesAssumedRole(roleArn, assumedRoleArn string) bool {
	roleArnParts := strings.Split(roleArn, ":role/")
	if len(roleArnParts) != 2 {
		return false
	}
	roleName := roleArnParts[1]
	if idx := strings.LastIndex(roleName, "/"); idx != -1 {
		roleName = roleName[idx+1:]
	}

	arnParts := strings.Split(roleArn, ":")
	if len(arnParts) < 5 {
		return false
	}
	account := arnParts[4]

	expectedPrefix := fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s", account, roleName)
	return assumedRoleArn == expectedPrefix ||
		strings.HasPrefix(assumedRoleArn, expectedPrefix+"/")
}

// convertRoleToAssumedRoleArn returns the assumed-role ARN prefix for a given
// IAM role ARN. The session-name suffix is omitted because the caller doesn't
// know which session will be used; consumers compare with HasPrefix.
//
//	in:  arn:aws:iam::ACCOUNT:role/[PATH/]ROLE-NAME
//	out: arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME
func convertRoleToAssumedRoleArn(roleArn, accountID string) string {
	parts := strings.Split(roleArn, "/")
	if len(parts) < 2 {
		return roleArn
	}
	roleName := parts[len(parts)-1]
	return fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s", accountID, roleName)
}

// assumedRoleARNToRoleARN converts an STS assumed-role ARN back to the IAM
// role ARN that it was assumed from. EKS APIs (Pod Identity, Access Entries)
// are keyed on IAM role ARNs, but `aws sts get-caller-identity` returns the
// STS form when called from inside an assumed role. Returns the input
// unchanged if it isn't an assumed-role ARN.
//
//	in:  arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME[/SESSION-NAME]
//	out: arn:aws:iam::ACCOUNT:role/ROLE-NAME
func assumedRoleARNToRoleARN(arn string) string {
	if !strings.Contains(arn, ":assumed-role/") {
		return arn
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	account := parts[4]
	// parts[5] is "assumed-role/ROLE-NAME[/SESSION-NAME]"
	tail := strings.TrimPrefix(parts[5], "assumed-role/")
	if i := strings.Index(tail, "/"); i != -1 {
		tail = tail[:i]
	}
	if tail == "" {
		return arn
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", account, tail)
}
