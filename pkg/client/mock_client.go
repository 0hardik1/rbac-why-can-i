package client

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
)

// MockRBACClient is a mock implementation of RBACClient for testing
type MockRBACClient struct {
	Roles               map[string]*rbacv1.RoleList // namespace -> RoleList
	ClusterRoles        *rbacv1.ClusterRoleList
	RoleBindings        map[string]*rbacv1.RoleBindingList // namespace -> RoleBindingList
	ClusterRoleBindings *rbacv1.ClusterRoleBindingList

	// Error simulation
	ListRolesError               error
	ListClusterRolesError        error
	ListRoleBindingsError        error
	ListClusterRoleBindingsError error
	GetRoleError                 error
	GetClusterRoleError          error
}

// NewMockRBACClient creates a new mock client with empty data
func NewMockRBACClient() *MockRBACClient {
	return &MockRBACClient{
		Roles:               make(map[string]*rbacv1.RoleList),
		ClusterRoles:        &rbacv1.ClusterRoleList{},
		RoleBindings:        make(map[string]*rbacv1.RoleBindingList),
		ClusterRoleBindings: &rbacv1.ClusterRoleBindingList{},
	}
}

func (m *MockRBACClient) ListRoles(ctx context.Context, namespace string) (*rbacv1.RoleList, error) {
	if m.ListRolesError != nil {
		return nil, m.ListRolesError
	}
	if roles, ok := m.Roles[namespace]; ok {
		return roles, nil
	}
	return &rbacv1.RoleList{}, nil
}

func (m *MockRBACClient) ListClusterRoles(ctx context.Context) (*rbacv1.ClusterRoleList, error) {
	if m.ListClusterRolesError != nil {
		return nil, m.ListClusterRolesError
	}
	if m.ClusterRoles == nil {
		return &rbacv1.ClusterRoleList{}, nil
	}
	return m.ClusterRoles, nil
}

func (m *MockRBACClient) ListRoleBindings(ctx context.Context, namespace string) (*rbacv1.RoleBindingList, error) {
	if m.ListRoleBindingsError != nil {
		return nil, m.ListRoleBindingsError
	}
	if bindings, ok := m.RoleBindings[namespace]; ok {
		return bindings, nil
	}
	return &rbacv1.RoleBindingList{}, nil
}

func (m *MockRBACClient) ListClusterRoleBindings(ctx context.Context) (*rbacv1.ClusterRoleBindingList, error) {
	if m.ListClusterRoleBindingsError != nil {
		return nil, m.ListClusterRoleBindingsError
	}
	if m.ClusterRoleBindings == nil {
		return &rbacv1.ClusterRoleBindingList{}, nil
	}
	return m.ClusterRoleBindings, nil
}

func (m *MockRBACClient) GetRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error) {
	if m.GetRoleError != nil {
		return nil, m.GetRoleError
	}
	if roles, ok := m.Roles[namespace]; ok {
		for _, role := range roles.Items {
			if role.Name == name {
				return &role, nil
			}
		}
	}
	return nil, fmt.Errorf("role %s not found in namespace %s", name, namespace)
}

func (m *MockRBACClient) GetClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error) {
	if m.GetClusterRoleError != nil {
		return nil, m.GetClusterRoleError
	}
	if m.ClusterRoles != nil {
		for _, cr := range m.ClusterRoles.Items {
			if cr.Name == name {
				return &cr, nil
			}
		}
	}
	return nil, fmt.Errorf("clusterrole %s not found", name)
}

// AddRole adds a role to the mock
func (m *MockRBACClient) AddRole(role rbacv1.Role) {
	ns := role.Namespace
	if _, ok := m.Roles[ns]; !ok {
		m.Roles[ns] = &rbacv1.RoleList{}
	}
	m.Roles[ns].Items = append(m.Roles[ns].Items, role)
}

// AddClusterRole adds a cluster role to the mock
func (m *MockRBACClient) AddClusterRole(cr rbacv1.ClusterRole) {
	if m.ClusterRoles == nil {
		m.ClusterRoles = &rbacv1.ClusterRoleList{}
	}
	m.ClusterRoles.Items = append(m.ClusterRoles.Items, cr)
}

// AddRoleBinding adds a role binding to the mock
func (m *MockRBACClient) AddRoleBinding(rb rbacv1.RoleBinding) {
	ns := rb.Namespace
	if _, ok := m.RoleBindings[ns]; !ok {
		m.RoleBindings[ns] = &rbacv1.RoleBindingList{}
	}
	m.RoleBindings[ns].Items = append(m.RoleBindings[ns].Items, rb)
}

// AddClusterRoleBinding adds a cluster role binding to the mock
func (m *MockRBACClient) AddClusterRoleBinding(crb rbacv1.ClusterRoleBinding) {
	if m.ClusterRoleBindings == nil {
		m.ClusterRoleBindings = &rbacv1.ClusterRoleBindingList{}
	}
	m.ClusterRoleBindings.Items = append(m.ClusterRoleBindings.Items, crb)
}
