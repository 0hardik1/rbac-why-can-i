package cani

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
)

// newOrchestrateOptions assembles a minimal *RbacWhyOptions with a current
// AWS-IAM context, suitable for driving orchestrateAWSIdentity in tests.
func newOrchestrateOptions(arn string) *RbacWhyOptions {
	return &RbacWhyOptions{
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		IOStreams: genericclioptions.IOStreams{
			In:     bytes.NewBuffer(nil),
			Out:    bytes.NewBuffer(nil),
			ErrOut: bytes.NewBuffer(nil),
		},
		CurrentContext: &ContextInfo{
			AuthMethod:     "aws-iam",
			AWSIamArn:      arn,
			EKSClusterName: "my-cluster",
			EKSRegion:      "us-east-1",
		},
	}
}

func TestOrchestrate_AccessEntryWins(t *testing.T) {
	o := newOrchestrateOptions("arn:aws:iam::1:role/admin")
	fakeEKS := &fakeEKSClient{
		describeAccessEntry: func(_ *eks.DescribeAccessEntryInput) (*eks.DescribeAccessEntryOutput, error) {
			return &eks.DescribeAccessEntryOutput{AccessEntry: &ekstypes.AccessEntry{
				PrincipalArn:     aws.String("arn:aws:iam::1:role/admin"),
				Username:         aws.String("admin@example.com"),
				KubernetesGroups: []string{"system:masters"},
				Type:             aws.String("STANDARD"),
			}}, nil
		},
		listAssociatedAccessPolicies: func(_ *eks.ListAssociatedAccessPoliciesInput) (*eks.ListAssociatedAccessPoliciesOutput, error) {
			return &eks.ListAssociatedAccessPoliciesOutput{}, nil
		},
	}
	// restConfig isn't consulted in this path (Access Entry hits first),
	// but pass a non-nil one to exercise the real signature.
	o.orchestrateAWSIdentity(context.Background(), &rest.Config{}, fakeEKS)

	if o.As != "admin@example.com" {
		t.Errorf("As = %q, want admin@example.com", o.As)
	}
	if o.CurrentContext.AuthMethod != "aws-iam (via Access Entry)" {
		t.Errorf("AuthMethod = %q", o.CurrentContext.AuthMethod)
	}
	if !o.CurrentContext.AccessEntryFound {
		t.Errorf("AccessEntryFound should be true")
	}
}

func TestOrchestrate_PodIdentityIsInformationalOnly(t *testing.T) {
	// Caller assumed an IAM role; no Access Entry, no aws-auth match; Pod
	// Identity has an association for that role. Pod Identity must NOT
	// rewrite the caller's identity (it supplies AWS credentials to pods,
	// it does not authenticate this caller as the ServiceAccount); it is
	// surfaced informationally while the identity falls through to the raw
	// IAM ARN.
	arn := "arn:aws:sts::1:assumed-role/MyRole/sess"
	o := newOrchestrateOptions(arn)

	fakeEKS := &fakeEKSClient{
		describeAccessEntry: func(_ *eks.DescribeAccessEntryInput) (*eks.DescribeAccessEntryOutput, error) {
			return nil, &ekstypes.ResourceNotFoundException{}
		},
		listPodIdentity: func(_ *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				{AssociationId: aws.String("a-1"), Namespace: aws.String("apps"), ServiceAccount: aws.String("worker")},
			}}, nil
		},
		describePodIdentity: func(in *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
			return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{
				AssociationId:  in.AssociationId,
				Namespace:      aws.String("apps"),
				ServiceAccount: aws.String("worker"),
				RoleArn:        aws.String("arn:aws:iam::1:role/MyRole"),
			}}, nil
		},
	}

	o.orchestrateAWSIdentity(context.Background(), &rest.Config{Host: "http://invalid.invalid"}, fakeEKS)

	if o.As != arn {
		t.Errorf("As = %q, want raw IAM ARN %q", o.As, arn)
	}
	if o.CurrentContext.AuthMethod != "aws-iam (no mapping found)" {
		t.Errorf("AuthMethod = %q", o.CurrentContext.AuthMethod)
	}
	if o.CurrentContext.PodIdentityForRole == nil ||
		o.CurrentContext.PodIdentityForRole.ServiceAccount != "worker" {
		t.Errorf("PodIdentityForRole not populated correctly: %+v", o.CurrentContext.PodIdentityForRole)
	}
}

func TestOrchestrate_FallsThroughToRawARN(t *testing.T) {
	// Nothing matches: Access Entry not found, aws-auth not readable
	// (real error), Pod Identity has zero matches.
	o := newOrchestrateOptions("arn:aws:iam::1:role/orphan")
	fakeEKS := &fakeEKSClient{
		describeAccessEntry: func(_ *eks.DescribeAccessEntryInput) (*eks.DescribeAccessEntryOutput, error) {
			return nil, &ekstypes.ResourceNotFoundException{}
		},
		listPodIdentity: func(_ *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			return &eks.ListPodIdentityAssociationsOutput{}, nil
		},
		describePodIdentity: func(in *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
			return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{}}, nil
		},
	}
	o.orchestrateAWSIdentity(context.Background(), &rest.Config{Host: "http://invalid.invalid"}, fakeEKS)
	if o.As != "arn:aws:iam::1:role/orphan" {
		t.Errorf("As = %q, want raw IAM ARN fallback", o.As)
	}
	if o.CurrentContext.AuthMethod != "aws-iam (no mapping found)" {
		t.Errorf("AuthMethod = %q", o.CurrentContext.AuthMethod)
	}
}

// TestFindMappingForArn_AssumedRole exercises the aws-auth ConfigMap
// matcher used by orchestrate's step 2. Full end-to-end exercise of the
// legacy path is via e2e tests against a real cluster fixture.
func TestFindMappingForArn_AssumedRole(t *testing.T) {
	mappings := []AWSAuthMapping{{
		RoleARN:  "arn:aws:iam::1:role/admin",
		Username: "admin",
		Groups:   []string{"system:masters"},
	}}
	id := findMappingForArn(mappings, "arn:aws:sts::1:assumed-role/admin/sess", true)
	if id == nil || !id.Found || id.Username != "admin" {
		t.Fatalf("expected match, got %+v", id)
	}
}
