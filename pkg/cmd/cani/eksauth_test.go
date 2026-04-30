package cani

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

// fakeEKSClient is a hand-rolled implementation of EKSAPI for tests.
type fakeEKSClient struct {
	describeAccessEntry          func(*eks.DescribeAccessEntryInput) (*eks.DescribeAccessEntryOutput, error)
	listAssociatedAccessPolicies func(*eks.ListAssociatedAccessPoliciesInput) (*eks.ListAssociatedAccessPoliciesOutput, error)
	listPodIdentity              func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error)
	describePodIdentity          func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error)
}

func (f *fakeEKSClient) DescribeAccessEntry(_ context.Context, in *eks.DescribeAccessEntryInput, _ ...func(*eks.Options)) (*eks.DescribeAccessEntryOutput, error) {
	return f.describeAccessEntry(in)
}
func (f *fakeEKSClient) ListAssociatedAccessPolicies(_ context.Context, in *eks.ListAssociatedAccessPoliciesInput, _ ...func(*eks.Options)) (*eks.ListAssociatedAccessPoliciesOutput, error) {
	return f.listAssociatedAccessPolicies(in)
}
func (f *fakeEKSClient) ListPodIdentityAssociations(_ context.Context, in *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	return f.listPodIdentity(in)
}
func (f *fakeEKSClient) DescribePodIdentityAssociation(_ context.Context, in *eks.DescribePodIdentityAssociationInput, _ ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	return f.describePodIdentity(in)
}

func TestResolveAccessEntryIdentity_Found(t *testing.T) {
	fake := &fakeEKSClient{
		describeAccessEntry: func(in *eks.DescribeAccessEntryInput) (*eks.DescribeAccessEntryOutput, error) {
			if *in.PrincipalArn != "arn:aws:iam::1:role/r" {
				t.Fatalf("unexpected principal: %s", *in.PrincipalArn)
			}
			return &eks.DescribeAccessEntryOutput{AccessEntry: &ekstypes.AccessEntry{
				PrincipalArn:     aws.String("arn:aws:iam::1:role/r"),
				Username:         aws.String("admin@example.com"),
				KubernetesGroups: []string{"system:masters"},
				Type:             aws.String("STANDARD"),
			}}, nil
		},
		listAssociatedAccessPolicies: func(_ *eks.ListAssociatedAccessPoliciesInput) (*eks.ListAssociatedAccessPoliciesOutput, error) {
			return &eks.ListAssociatedAccessPoliciesOutput{
				AssociatedAccessPolicies: []ekstypes.AssociatedAccessPolicy{{
					PolicyArn: aws.String("arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"),
					AccessScope: &ekstypes.AccessScope{
						Type: ekstypes.AccessScopeTypeCluster,
					},
				}},
			}, nil
		},
	}
	id, err := ResolveAccessEntryIdentity(context.Background(), fake, "c", "arn:aws:iam::1:role/r")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !id.Found || id.KubernetesUsername != "admin@example.com" || len(id.KubernetesGroups) != 1 {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if len(id.AccessPolicies) != 1 || id.AccessPolicies[0].ScopeType != "cluster" {
		t.Fatalf("unexpected policies: %+v", id.AccessPolicies)
	}
}

func TestResolveAccessEntryIdentity_NotFound(t *testing.T) {
	fake := &fakeEKSClient{
		describeAccessEntry: func(_ *eks.DescribeAccessEntryInput) (*eks.DescribeAccessEntryOutput, error) {
			return nil, &ekstypes.ResourceNotFoundException{Message: aws.String("nope")}
		},
	}
	id, err := ResolveAccessEntryIdentity(context.Background(), fake, "c", "arn:aws:iam::1:role/r")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if id.Found {
		t.Fatalf("expected not found")
	}
}

func TestResolveAccessEntryIdentity_OtherErrorBubbles(t *testing.T) {
	want := errors.New("AccessDenied")
	fake := &fakeEKSClient{
		describeAccessEntry: func(_ *eks.DescribeAccessEntryInput) (*eks.DescribeAccessEntryOutput, error) {
			return nil, want
		},
	}
	if _, err := ResolveAccessEntryIdentity(context.Background(), fake, "c", "arn:aws:iam::1:role/r"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestFindPodIdentityByRole_Match(t *testing.T) {
	listed := false
	fake := &fakeEKSClient{
		listPodIdentity: func(_ *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			if listed {
				return &eks.ListPodIdentityAssociationsOutput{}, nil
			}
			listed = true
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				{AssociationId: aws.String("a-1"), Namespace: aws.String("ns1"), ServiceAccount: aws.String("sa1")},
				{AssociationId: aws.String("a-2"), Namespace: aws.String("ns2"), ServiceAccount: aws.String("sa2")},
			}}, nil
		},
		describePodIdentity: func(in *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
			role := "arn:aws:iam::1:role/other"
			if *in.AssociationId == "a-2" {
				role = "arn:aws:iam::1:role/target"
			}
			return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{
				AssociationId:  in.AssociationId,
				Namespace:      aws.String("ns" + (*in.AssociationId)[len(*in.AssociationId)-1:]),
				ServiceAccount: aws.String("sa" + (*in.AssociationId)[len(*in.AssociationId)-1:]),
				RoleArn:        aws.String(role),
			}}, nil
		},
	}
	matches, err := FindPodIdentityByRole(context.Background(), fake, "c", "arn:aws:iam::1:role/target")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(matches) != 1 || matches[0].ServiceAccount != "sa2" {
		t.Fatalf("unexpected matches: %+v", matches)
	}
}

func TestFindPodIdentityByRole_NormalizesAssumedRole(t *testing.T) {
	fake := &fakeEKSClient{
		listPodIdentity: func(_ *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				{AssociationId: aws.String("a-1"), Namespace: aws.String("ns"), ServiceAccount: aws.String("sa")},
			}}, nil
		},
		describePodIdentity: func(in *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
			return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{
				AssociationId:  in.AssociationId,
				Namespace:      aws.String("ns"),
				ServiceAccount: aws.String("sa"),
				RoleArn:        aws.String("arn:aws:iam::1:role/MyRole"),
			}}, nil
		},
	}
	// caller passes the STS assumed-role ARN; expect a match.
	matches, err := FindPodIdentityByRole(context.Background(), fake, "c", "arn:aws:sts::1:assumed-role/MyRole/sess")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestFindPodIdentityByRole_NoMatch(t *testing.T) {
	fake := &fakeEKSClient{
		listPodIdentity: func(_ *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				{AssociationId: aws.String("a-1"), Namespace: aws.String("ns"), ServiceAccount: aws.String("sa")},
			}}, nil
		},
		describePodIdentity: func(in *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
			return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{
				AssociationId: in.AssociationId,
				RoleArn:       aws.String("arn:aws:iam::1:role/elsewhere"),
			}}, nil
		},
	}
	matches, err := FindPodIdentityByRole(context.Background(), fake, "c", "arn:aws:iam::1:role/target")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestFindPodIdentityForServiceAccount(t *testing.T) {
	gotInput := false
	fake := &fakeEKSClient{
		listPodIdentity: func(in *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			gotInput = true
			if in.Namespace == nil || *in.Namespace != "kube-system" {
				t.Errorf("expected namespace filter, got %v", in.Namespace)
			}
			if in.ServiceAccount == nil || *in.ServiceAccount != "my-sa" {
				t.Errorf("expected SA filter, got %v", in.ServiceAccount)
			}
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				{AssociationId: aws.String("a-1"), Namespace: aws.String("kube-system"), ServiceAccount: aws.String("my-sa")},
			}}, nil
		},
		describePodIdentity: func(in *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
			return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{
				AssociationId:  in.AssociationId,
				Namespace:      aws.String("kube-system"),
				ServiceAccount: aws.String("my-sa"),
				RoleArn:        aws.String("arn:aws:iam::1:role/r"),
			}}, nil
		},
	}
	out, err := FindPodIdentityForServiceAccount(context.Background(), fake, "c", "kube-system", "my-sa")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !gotInput {
		t.Fatal("list was not called")
	}
	if len(out) != 1 || out[0].RoleARN != "arn:aws:iam::1:role/r" {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestFindPodIdentity_EmptyInputsReturnNil(t *testing.T) {
	fake := &fakeEKSClient{}
	if r, err := FindPodIdentityByRole(context.Background(), fake, "", "x"); err != nil || r != nil {
		t.Errorf("FindPodIdentityByRole empty cluster: got (%v,%v)", r, err)
	}
	if r, err := FindPodIdentityForServiceAccount(context.Background(), fake, "c", "", "sa"); err != nil || r != nil {
		t.Errorf("FindPodIdentityForServiceAccount empty ns: got (%v,%v)", r, err)
	}
}

func TestIsResourceNotFound(t *testing.T) {
	if !isResourceNotFound(&ekstypes.ResourceNotFoundException{}) {
		t.Error("expected typed exception to match")
	}
	if isResourceNotFound(errors.New("other")) {
		t.Error("expected plain error to not match")
	}
}

func TestArnNormalization(t *testing.T) {
	if got := assumedRoleARNToRoleARN("arn:aws:sts::123:assumed-role/Foo/sess"); got != "arn:aws:iam::123:role/Foo" {
		t.Errorf("got %q", got)
	}
	if got := assumedRoleARNToRoleARN("arn:aws:iam::123:role/Foo"); got != "arn:aws:iam::123:role/Foo" {
		t.Errorf("non-assumed ARN should pass through, got %q", got)
	}
	if got := assumedRoleARNToRoleARN("arn:aws:sts::123:assumed-role/Foo"); got != "arn:aws:iam::123:role/Foo" {
		t.Errorf("got %q", got)
	}
}
