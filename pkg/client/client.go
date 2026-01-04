package client

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// RBACClient interface for Kubernetes RBAC operations
type RBACClient interface {
	ListRoles(ctx context.Context, namespace string) (*rbacv1.RoleList, error)
	ListClusterRoles(ctx context.Context) (*rbacv1.ClusterRoleList, error)
	ListRoleBindings(ctx context.Context, namespace string) (*rbacv1.RoleBindingList, error)
	ListClusterRoleBindings(ctx context.Context) (*rbacv1.ClusterRoleBindingList, error)
	GetRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error)
	GetClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error)
}

// K8sRBACClient implements RBACClient using the Kubernetes API
type K8sRBACClient struct {
	clientset kubernetes.Interface
}

// NewK8sRBACClient creates a new Kubernetes RBAC client
func NewK8sRBACClient(config *rest.Config) (*K8sRBACClient, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &K8sRBACClient{clientset: clientset}, nil
}

// NewK8sRBACClientFromClientset creates a client from an existing clientset
func NewK8sRBACClientFromClientset(clientset kubernetes.Interface) *K8sRBACClient {
	return &K8sRBACClient{clientset: clientset}
}

func (c *K8sRBACClient) ListRoles(ctx context.Context, namespace string) (*rbacv1.RoleList, error) {
	return c.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
}

func (c *K8sRBACClient) ListClusterRoles(ctx context.Context) (*rbacv1.ClusterRoleList, error) {
	return c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
}

func (c *K8sRBACClient) ListRoleBindings(ctx context.Context, namespace string) (*rbacv1.RoleBindingList, error) {
	return c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
}

func (c *K8sRBACClient) ListClusterRoleBindings(ctx context.Context) (*rbacv1.ClusterRoleBindingList, error) {
	return c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
}

func (c *K8sRBACClient) GetRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error) {
	return c.clientset.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *K8sRBACClient) GetClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error) {
	return c.clientset.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
}
