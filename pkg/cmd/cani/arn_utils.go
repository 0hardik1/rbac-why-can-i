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
	partition := arnParts[1]
	account := arnParts[4]

	expectedPrefix := fmt.Sprintf("arn:%s:sts::%s:assumed-role/%s", partition, account, roleName)
	return assumedRoleArn == expectedPrefix ||
		strings.HasPrefix(assumedRoleArn, expectedPrefix+"/")
}

// convertRoleToAssumedRoleArn returns the assumed-role ARN for a given IAM
// role ARN. Partition and account are taken from the role ARN itself so
// cross-account and non-standard-partition roles synthesize correctly;
// fallbackAccount is only used when the role ARN doesn't carry an account.
// sessionName is appended when known ("" omits it; consumers compare with
// HasPrefix).
//
//	in:  arn:PARTITION:iam::ACCOUNT:role/[PATH/]ROLE-NAME
//	out: arn:PARTITION:sts::ACCOUNT:assumed-role/ROLE-NAME[/SESSION-NAME]
func convertRoleToAssumedRoleArn(roleArn, fallbackAccount, sessionName string) string {
	slashParts := strings.Split(roleArn, "/")
	if len(slashParts) < 2 {
		return roleArn
	}
	roleName := slashParts[len(slashParts)-1]

	partition := "aws"
	account := fallbackAccount
	if colonParts := strings.Split(roleArn, ":"); len(colonParts) >= 5 {
		if colonParts[1] != "" {
			partition = colonParts[1]
		}
		if colonParts[4] != "" {
			account = colonParts[4]
		}
	}

	arn := fmt.Sprintf("arn:%s:sts::%s:assumed-role/%s", partition, account, roleName)
	if sessionName != "" {
		arn += "/" + sessionName
	}
	return arn
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
	partition := parts[1]
	account := parts[4]
	// parts[5] is "assumed-role/ROLE-NAME[/SESSION-NAME]"
	tail := strings.TrimPrefix(parts[5], "assumed-role/")
	if i := strings.Index(tail, "/"); i != -1 {
		tail = tail[:i]
	}
	if tail == "" {
		return arn
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, account, tail)
}
