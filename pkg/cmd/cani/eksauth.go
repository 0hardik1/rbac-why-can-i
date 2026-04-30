package cani

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/smithy-go"
)

// EKSAPI is the subset of *eks.Client used by this package. It's defined
// narrowly so unit tests can substitute a fake without depending on the SDK
// client constructor.
type EKSAPI interface {
	DescribeAccessEntry(ctx context.Context, in *eks.DescribeAccessEntryInput, optFns ...func(*eks.Options)) (*eks.DescribeAccessEntryOutput, error)
	ListAssociatedAccessPolicies(ctx context.Context, in *eks.ListAssociatedAccessPoliciesInput, optFns ...func(*eks.Options)) (*eks.ListAssociatedAccessPoliciesOutput, error)
	ListPodIdentityAssociations(ctx context.Context, in *eks.ListPodIdentityAssociationsInput, optFns ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
	DescribePodIdentityAssociation(ctx context.Context, in *eks.DescribePodIdentityAssociationInput, optFns ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
}

// NewEKSClient builds a real *eks.Client using the default AWS credential
// chain (env vars, shared config, IMDS, etc.). The profile and region come
// from kubeconfig discovery and/or user-supplied flags.
func NewEKSClient(ctx context.Context, profile, region string) (EKSAPI, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(region))
	}
	if profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return eks.NewFromConfig(cfg), nil
}

// AccessPolicyAssociation is a flattened view of an EKS-managed access
// policy attached to an Access Entry. Surfaced to users informationally
// because these grant K8s permissions out-of-band of the standard
// (Cluster)RoleBinding chain that rbac-why walks.
type AccessPolicyAssociation struct {
	PolicyARN  string
	ScopeType  string   // "cluster" or "namespace"
	Namespaces []string // populated when ScopeType == "namespace"
}

// AccessEntryIdentity is the resolved identity from an EKS Access Entry.
type AccessEntryIdentity struct {
	Found              bool
	PrincipalARN       string
	Type               string
	KubernetesUsername string
	KubernetesGroups   []string
	AccessPolicies     []AccessPolicyAssociation
}

// PodIdentityAssociation is a concise view of an EKS Pod Identity
// association.
type PodIdentityAssociation struct {
	AssociationID  string
	Namespace      string
	ServiceAccount string
	RoleARN        string
}

// ErrEKSResourceNotFound is returned when the EKS API reports that a
// requested resource doesn't exist (e.g. no Access Entry for the principal,
// or the cluster doesn't exist). Callers treat this as "no match — try the
// next resolution step", not as a hard error.
var ErrEKSResourceNotFound = errors.New("EKS resource not found")

// ResolveAccessEntryIdentity looks up an Access Entry for the given IAM
// principal ARN. Returns Found=false when no Access Entry exists for the
// principal. Errors other than ResourceNotFound (e.g. AccessDenied,
// throttling) are returned to the caller, which decides whether to warn
// and continue or fail.
func ResolveAccessEntryIdentity(ctx context.Context, client EKSAPI, clusterName, principalARN string) (*AccessEntryIdentity, error) {
	if clusterName == "" || principalARN == "" {
		return &AccessEntryIdentity{Found: false}, nil
	}

	out, err := client.DescribeAccessEntry(ctx, &eks.DescribeAccessEntryInput{
		ClusterName:  aws.String(clusterName),
		PrincipalArn: aws.String(principalARN),
	})
	if err != nil {
		if isResourceNotFound(err) {
			return &AccessEntryIdentity{Found: false}, nil
		}
		return nil, err
	}
	if out == nil || out.AccessEntry == nil {
		return &AccessEntryIdentity{Found: false}, nil
	}

	id := &AccessEntryIdentity{
		Found:              true,
		PrincipalARN:       deref(out.AccessEntry.PrincipalArn),
		Type:               deref(out.AccessEntry.Type),
		KubernetesUsername: deref(out.AccessEntry.Username),
		KubernetesGroups:   out.AccessEntry.KubernetesGroups,
	}

	policies, err := listAssociatedAccessPolicies(ctx, client, clusterName, principalARN)
	if err != nil {
		// Surface the policy-list error as part of the identity result —
		// the username/groups are still authoritative; the policies are
		// informational.
		return id, fmt.Errorf("retrieved access entry but failed to list associated policies: %w", err)
	}
	id.AccessPolicies = policies
	return id, nil
}

func listAssociatedAccessPolicies(ctx context.Context, client EKSAPI, clusterName, principalARN string) ([]AccessPolicyAssociation, error) {
	var result []AccessPolicyAssociation
	var nextToken *string
	for {
		out, err := client.ListAssociatedAccessPolicies(ctx, &eks.ListAssociatedAccessPoliciesInput{
			ClusterName:  aws.String(clusterName),
			PrincipalArn: aws.String(principalARN),
			NextToken:    nextToken,
		})
		if err != nil {
			if isResourceNotFound(err) {
				return result, nil
			}
			return nil, err
		}
		for _, p := range out.AssociatedAccessPolicies {
			ap := AccessPolicyAssociation{PolicyARN: deref(p.PolicyArn)}
			if p.AccessScope != nil {
				ap.ScopeType = string(p.AccessScope.Type)
				ap.Namespaces = p.AccessScope.Namespaces
			}
			result = append(result, ap)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		nextToken = out.NextToken
	}
}

// FindPodIdentityByRole returns Pod Identity Associations whose IAM role
// ARN matches roleARN. The caller may pass either an IAM role ARN
// (arn:aws:iam:::role/...) or an STS assumed-role ARN
// (arn:aws:sts:::assumed-role/...); both are normalized.
//
// The list endpoint summaries don't include RoleArn, so we describe each
// summary. We cap the number of describes at maxPodIdentityScans to bound
// API cost on clusters with many associations; if the cap is hit we return
// what we found plus a non-nil error indicating the scan was truncated.
const maxPodIdentityScans = 500

func FindPodIdentityByRole(ctx context.Context, client EKSAPI, clusterName, roleARN string) ([]PodIdentityAssociation, error) {
	if clusterName == "" || roleARN == "" {
		return nil, nil
	}
	target := assumedRoleARNToRoleARN(roleARN)

	var matches []PodIdentityAssociation
	scanned := 0
	var nextToken *string
	for {
		out, err := client.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
			ClusterName: aws.String(clusterName),
			NextToken:   nextToken,
		})
		if err != nil {
			if isResourceNotFound(err) {
				return matches, nil
			}
			return nil, err
		}
		for _, summary := range out.Associations {
			if scanned >= maxPodIdentityScans {
				return matches, fmt.Errorf("scanned %d Pod Identity associations without exhausting the list; results may be incomplete", scanned)
			}
			scanned++
			full, err := describeAssociation(ctx, client, clusterName, deref(summary.AssociationId))
			if err != nil {
				return matches, err
			}
			if full == nil {
				continue
			}
			if deref(full.RoleArn) == target {
				matches = append(matches, PodIdentityAssociation{
					AssociationID:  deref(full.AssociationId),
					Namespace:      deref(full.Namespace),
					ServiceAccount: deref(full.ServiceAccount),
					RoleARN:        deref(full.RoleArn),
				})
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return matches, nil
		}
		nextToken = out.NextToken
	}
}

// FindPodIdentityForServiceAccount returns Pod Identity Associations bound
// to the given namespace+ServiceAccount. Used to enrich rbac-why output
// when the resolved subject is a ServiceAccount.
func FindPodIdentityForServiceAccount(ctx context.Context, client EKSAPI, clusterName, namespace, serviceAccount string) ([]PodIdentityAssociation, error) {
	if clusterName == "" || namespace == "" || serviceAccount == "" {
		return nil, nil
	}

	var result []PodIdentityAssociation
	var nextToken *string
	for {
		out, err := client.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
			ClusterName:    aws.String(clusterName),
			Namespace:      aws.String(namespace),
			ServiceAccount: aws.String(serviceAccount),
			NextToken:      nextToken,
		})
		if err != nil {
			if isResourceNotFound(err) {
				return result, nil
			}
			return nil, err
		}
		for _, summary := range out.Associations {
			full, err := describeAssociation(ctx, client, clusterName, deref(summary.AssociationId))
			if err != nil {
				return result, err
			}
			if full == nil {
				continue
			}
			result = append(result, PodIdentityAssociation{
				AssociationID:  deref(full.AssociationId),
				Namespace:      deref(full.Namespace),
				ServiceAccount: deref(full.ServiceAccount),
				RoleARN:        deref(full.RoleArn),
			})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		nextToken = out.NextToken
	}
}

func describeAssociation(ctx context.Context, client EKSAPI, clusterName, associationID string) (*ekstypes.PodIdentityAssociation, error) {
	if associationID == "" {
		return nil, nil
	}
	out, err := client.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
		ClusterName:   aws.String(clusterName),
		AssociationId: aws.String(associationID),
	})
	if err != nil {
		if isResourceNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if out == nil {
		return nil, nil
	}
	return out.Association, nil
}

// isResourceNotFound returns true if the error is a ResourceNotFoundException
// from the EKS API. SDK v2 wraps this in a smithy.APIError; check both the
// typed exception and the error code as a belt-and-braces measure.
func isResourceNotFound(err error) bool {
	var rnf *ekstypes.ResourceNotFoundException
	if errors.As(err, &rnf) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ResourceNotFoundException"
	}
	return false
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
