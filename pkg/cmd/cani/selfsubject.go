package cani

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// resolveSelfSubject asks the API server who the current credentials
// authenticate as, via a SelfSubjectReview. This is the authoritative way to
// learn the username and groups for token, exec, and OIDC authentication,
// where the kubeconfig alone can't tell us.
func resolveSelfSubject(ctx context.Context, restConfig *rest.Config) (string, []string, error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	review, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return "", nil, err
	}

	userInfo := review.Status.UserInfo
	if userInfo.Username == "" {
		return "", nil, fmt.Errorf("API server returned an empty username")
	}
	return userInfo.Username, userInfo.Groups, nil
}
