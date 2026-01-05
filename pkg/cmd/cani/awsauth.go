package cani

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// AWSAuthMapping represents a mapping entry in the aws-auth ConfigMap
type AWSAuthMapping struct {
	RoleARN  string   `yaml:"rolearn,omitempty"`
	UserARN  string   `yaml:"userarn,omitempty"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups,omitempty"`
}

// AWSAuthIdentity represents the resolved Kubernetes identity from aws-auth
type AWSAuthIdentity struct {
	Username string
	Groups   []string
	Found    bool
}

// ResolveAWSAuthIdentity looks up an IAM ARN in the aws-auth ConfigMap
// and returns the mapped Kubernetes username and groups
func ResolveAWSAuthIdentity(ctx context.Context, restConfig *rest.Config, iamArn string) (*AWSAuthIdentity, error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Read the aws-auth ConfigMap from kube-system namespace
	cm, err := clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get aws-auth ConfigMap: %w", err)
	}

	// Parse mapRoles
	if mapRolesData, ok := cm.Data["mapRoles"]; ok {
		var mappings []AWSAuthMapping
		if err := yaml.Unmarshal([]byte(mapRolesData), &mappings); err == nil {
			if identity := findMappingForArn(mappings, iamArn, true); identity != nil {
				return identity, nil
			}
		}
	}

	// Parse mapUsers
	if mapUsersData, ok := cm.Data["mapUsers"]; ok {
		var mappings []AWSAuthMapping
		if err := yaml.Unmarshal([]byte(mapUsersData), &mappings); err == nil {
			if identity := findMappingForArn(mappings, iamArn, false); identity != nil {
				return identity, nil
			}
		}
	}

	// Not found in aws-auth - return default behavior
	// EKS uses the IAM ARN as the username if not mapped
	return &AWSAuthIdentity{
		Username: iamArn,
		Groups:   nil,
		Found:    false,
	}, nil
}

// findMappingForArn searches for a matching ARN in the mappings
// For roles, it handles the assumed-role format matching
func findMappingForArn(mappings []AWSAuthMapping, iamArn string, isRoleMapping bool) *AWSAuthIdentity {
	for _, mapping := range mappings {
		var mappingArn string
		if isRoleMapping {
			mappingArn = mapping.RoleARN
		} else {
			mappingArn = mapping.UserARN
		}

		if mappingArn == "" {
			continue
		}

		// Check for exact match
		if mappingArn == iamArn {
			return &AWSAuthIdentity{
				Username: resolveUsername(mapping.Username, iamArn),
				Groups:   mapping.Groups,
				Found:    true,
			}
		}

		// For roles, check if the iamArn is an assumed-role version of the mappingArn
		// mappingArn: arn:aws:iam::123456789012:role/my-role
		// iamArn:     arn:aws:sts::123456789012:assumed-role/my-role or
		//             arn:aws:sts::123456789012:assumed-role/my-role/session-name
		if isRoleMapping && matchesAssumedRole(mappingArn, iamArn) {
			return &AWSAuthIdentity{
				Username: resolveUsername(mapping.Username, iamArn),
				Groups:   mapping.Groups,
				Found:    true,
			}
		}
	}

	return nil
}

// matchesAssumedRole checks if an assumed-role ARN matches a role ARN
// roleArn: arn:aws:iam::123456789012:role/my-role
// assumedRoleArn: arn:aws:sts::123456789012:assumed-role/my-role[/session-name]
func matchesAssumedRole(roleArn, assumedRoleArn string) bool {
	// Extract role name from role ARN
	// Format: arn:aws:iam::ACCOUNT:role/ROLE-NAME or arn:aws:iam::ACCOUNT:role/PATH/ROLE-NAME
	roleArnParts := strings.Split(roleArn, ":role/")
	if len(roleArnParts) != 2 {
		return false
	}
	roleName := roleArnParts[1]
	// Handle paths in role name (e.g., "path/to/role-name" -> "role-name")
	if idx := strings.LastIndex(roleName, "/"); idx != -1 {
		roleName = roleName[idx+1:]
	}

	// Extract account from role ARN
	arnParts := strings.Split(roleArn, ":")
	if len(arnParts) < 5 {
		return false
	}
	account := arnParts[4]

	// Check if assumed-role ARN matches the pattern
	// Format: arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME[/SESSION-NAME]
	expectedPrefix := fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s", account, roleName)
	return assumedRoleArn == expectedPrefix ||
		strings.HasPrefix(assumedRoleArn, expectedPrefix+"/")
}

// resolveUsername handles the username template variables
// Supports: {{AccountID}}, {{SessionName}}, etc.
func resolveUsername(usernameTemplate, iamArn string) string {
	if usernameTemplate == "" {
		return iamArn
	}

	result := usernameTemplate

	// Extract account ID from ARN
	arnParts := strings.Split(iamArn, ":")
	if len(arnParts) >= 5 {
		result = strings.ReplaceAll(result, "{{AccountID}}", arnParts[4])
	}

	// Extract session name for assumed roles
	// Format: arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME/SESSION-NAME
	if strings.Contains(iamArn, ":assumed-role/") {
		parts := strings.Split(iamArn, "/")
		if len(parts) >= 3 {
			sessionName := parts[len(parts)-1]
			result = strings.ReplaceAll(result, "{{SessionName}}", sessionName)
		}
	}

	return result
}
