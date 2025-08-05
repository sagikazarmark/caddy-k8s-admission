package admission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestAlwaysAllow_CaddyModule(t *testing.T) {
	module := AlwaysAllow{}
	moduleInfo := module.CaddyModule()

	assert.Equal(t, caddy.ModuleID("k8s.admission.always_allow"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(AlwaysAllow),
		moduleInfo.New(),
		"Module constructor should return AlwaysAllow instance",
	)
}

func TestAlwaysAllow_Admit(t *testing.T) {
	uid := types.UID("test-uid")

	testCases := []struct {
		name   string
		review admissionv1.AdmissionReview
	}{
		{
			name: "basic pod creation",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: uid,
					Kind: metav1.GroupVersionKind{
						Version: "v1",
						Kind:    "Pod",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`),
					},
				},
			},
		},
		{
			name: "service update",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: uid,
					Kind: metav1.GroupVersionKind{
						Version: "v1",
						Kind:    "Service",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(
							`{"apiVersion":"v1","kind":"Service","metadata":{"name":"test"}}`,
						),
					},
				},
			},
		},
		{
			name: "deployment deletion",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: uid,
					Kind: metav1.GroupVersionKind{
						Group:   "apps",
						Version: "v1",
						Kind:    "Deployment",
					},
					Operation: admissionv1.Delete,
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := AlwaysAllow{}
			response, err := handler.Admit(context.Background(), testCase.review)

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, uid, response.UID)
			assert.True(t, response.Allowed)
			assert.Nil(t, response.Result)
			assert.Nil(t, response.Patch)
			assert.Nil(t, response.PatchType)
		})
	}
}

func TestAlwaysDeny_CaddyModule(t *testing.T) {
	module := AlwaysDeny{}
	moduleInfo := module.CaddyModule()

	assert.Equal(t, caddy.ModuleID("k8s.admission.always_deny"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(AlwaysDeny),
		moduleInfo.New(),
		"Module constructor should return AlwaysDeny instance",
	)
}

func TestAlwaysDeny_Admit(t *testing.T) {
	uid := types.UID("test-uid")

	testCases := []struct {
		name   string
		review admissionv1.AdmissionReview
	}{
		{
			name: "basic pod creation",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: uid,
					Kind: metav1.GroupVersionKind{
						Version: "v1",
						Kind:    "Pod",
					},
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`),
					},
				},
			},
		},
		{
			name: "configmap update",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: uid,
					Kind: metav1.GroupVersionKind{
						Version: "v1",
						Kind:    "ConfigMap",
					},
					Operation: admissionv1.Update,
					Object: runtime.RawExtension{
						Raw: []byte(
							`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test"}}`,
						),
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := AlwaysDeny{}
			response, err := handler.Admit(context.Background(), testCase.review)

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, uid, response.UID)
			assert.False(t, response.Allowed)
			assert.Nil(t, response.Result)
			assert.Nil(t, response.Patch)
			assert.Nil(t, response.PatchType)
		})
	}
}

// TestControllersModuleRegistration ensures all controllers are properly registered as Caddy modules
func TestControllersModuleRegistration(t *testing.T) {
	// This test verifies that the init() function properly registers all controller modules
	// We can't directly test the init() function, but we can verify the modules are available

	testCases := []struct {
		name     string
		moduleID caddy.ModuleID
		module   caddy.Module
	}{
		{
			name:     "AlwaysAllow",
			moduleID: "k8s.admission.always_allow",
			module:   &AlwaysAllow{},
		},
		{
			name:     "AlwaysDeny",
			moduleID: "k8s.admission.always_deny",
			module:   &AlwaysDeny{},
		},
		{
			name:     "ValidationPolicy",
			moduleID: "k8s.admission.validation_policy",
			module:   &ValidationPolicy{},
		},
		{
			name:     "JSONPatchController",
			moduleID: "k8s.admission.json_patch",
			module:   &JSONPatcher{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			moduleInfo := testCase.module.CaddyModule()
			assert.Equal(t, caddy.ModuleID(testCase.moduleID), moduleInfo.ID)
			assert.NotNil(t, moduleInfo.New)
		})
	}
}

// TestAlwaysAllow_ResponseConsistency tests that AlwaysAllow always returns consistent responses
func TestAlwaysAllow_ResponseConsistency(t *testing.T) {
	handler := AlwaysAllow{}
	uid := types.UID("consistency-test")

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: uid,
			Kind: metav1.GroupVersionKind{
				Version: "v1",
				Kind:    "Pod",
			},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`),
			},
		},
	}

	// Run multiple times to ensure consistency
	for range 5 {
		response, err := handler.Admit(context.Background(), review)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Allowed)
		assert.Equal(t, uid, response.UID)
	}
}

// TestAlwaysDeny_ResponseConsistency tests that AlwaysDeny always returns consistent responses
func TestAlwaysDeny_ResponseConsistency(t *testing.T) {
	handler := AlwaysDeny{}
	uid := types.UID("consistency-test")

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: uid,
			Kind: metav1.GroupVersionKind{
				Version: "v1",
				Kind:    "Pod",
			},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`),
			},
		},
	}

	// Run multiple times to ensure consistency
	for range 5 {
		response, err := handler.Admit(context.Background(), review)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.False(t, response.Allowed)
		assert.Equal(t, uid, response.UID)
	}
}

// TestControllersConcurrency tests that controllers are safe for concurrent use
func TestControllersConcurrency(t *testing.T) {
	uid := types.UID("concurrent-test")
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: uid,
			Kind: metav1.GroupVersionKind{
				Version: "v1",
				Kind:    "Pod",
			},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`),
			},
		},
	}

	t.Run("AlwaysAllow concurrent", func(t *testing.T) {
		handler := AlwaysAllow{}

		done := make(chan bool, 10)
		for range 10 {
			go func() {
				defer func() { done <- true }()
				response, err := handler.Admit(context.Background(), review)
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.True(t, response.Allowed)
				assert.Equal(t, uid, response.UID)
			}()
		}

		for range 10 {
			<-done
		}
	})

	t.Run("AlwaysDeny concurrent", func(t *testing.T) {
		handler := AlwaysDeny{}

		done := make(chan bool, 10)
		for range 10 {
			go func() {
				defer func() { done <- true }()
				response, err := handler.Admit(context.Background(), review)
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.False(t, response.Allowed)
				assert.Equal(t, uid, response.UID)
			}()
		}

		for range 10 {
			<-done
		}
	})
}

func TestValidationPolicy_CaddyModule(t *testing.T) {
	policy := ValidationPolicy{}
	moduleInfo := policy.CaddyModule()

	assert.Equal(t, caddy.ModuleID("k8s.admission.validation_policy"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(ValidationPolicy),
		moduleInfo.New(),
		"Module constructor should return ValidationPolicy instance",
	)
}

func TestValidationPolicy_Provision(t *testing.T) {
	testCases := []struct {
		name        string
		expression  string
		expectError bool
	}{
		{
			name:        "valid boolean expression",
			expression:  "true",
			expectError: false,
		},
		{
			name:        "valid expression with variables",
			expression:  "name == 'test-pod'",
			expectError: false,
		},
		{
			name:        "valid complex expression",
			expression:  "operation == 'CREATE' && has(object.metadata) && object.metadata.name.startsWith('prod-')",
			expectError: false,
		},
		{
			name:        "invalid expression syntax",
			expression:  "name == ",
			expectError: true,
		},
		{
			name:        "expression returning non-boolean",
			expression:  "name",
			expectError: true,
		},
		{
			name:        "expression with unsupported variable",
			expression:  "unsupported_var == 'test'",
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &ValidationPolicy{
				Expression: testCase.expression,
				Action:     PolicyActionAllow,
			}

			err := policy.Provision(caddy.Context{})

			if testCase.expectError {
				assert.Error(t, err)
				assert.Nil(t, policy.program)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, policy.program)
			}
		})
	}
}

func TestValidationPolicy_UnmarshalCaddyfile(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedExpr   string
		expectedAction PolicyAction
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "valid policy with allow action",
			input: `validation_policy {
				expression "name == 'allowed-pod'"
				action allow
			}`,
			expectedExpr:   "name == 'allowed-pod'",
			expectedAction: PolicyActionAllow,
			expectError:    false,
		},
		{
			name: "valid policy with deny action",
			input: `validation_policy {
				expression "operation == 'DELETE'"
				action deny
			}`,
			expectedExpr:   "operation == 'DELETE'",
			expectedAction: PolicyActionDeny,
			expectError:    false,
		},
		{
			name: "invalid action",
			input: `validation_policy {
				expression "true"
				action invalid
			}`,
			expectError:    true,
			expectedErrMsg: "invalid action 'invalid'",
		},
		{
			name: "unknown directive",
			input: `validation_policy {
				unknown_directive value
			}`,
			expectError:    true,
			expectedErrMsg: "unknown directive: unknown_directive",
		},
		{
			name: "missing expression argument",
			input: `validation_policy {
				expression
			}`,
			expectError: true,
		},
		{
			name: "missing action argument",
			input: `validation_policy {
				action
			}`,
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &ValidationPolicy{}
			d := caddyfile.NewTestDispenser(testCase.input)
			d.Next() // advance to the directive name

			err := policy.UnmarshalCaddyfile(d)

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), testCase.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.expectedExpr, policy.Expression)
				assert.Equal(t, testCase.expectedAction, policy.Action)
			}
		})
	}
}

func TestValidationPolicy_Admit(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name        string
		expression  string
		action      PolicyAction
		review      admissionv1.AdmissionReview
		expectAllow bool
		expectError bool
		errorMsg    string
	}{
		{
			name:       "allow action with matching policy",
			expression: "operation == 'CREATE'",
			action:     PolicyActionAllow,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
			expectError: false,
		},
		{
			name:       "allow action with non-matching policy",
			expression: "operation == 'DELETE'",
			action:     PolicyActionAllow,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true, // policy doesn't match, so allow
			expectError: false,
		},
		{
			name:       "deny action with matching policy",
			expression: "operation == 'DELETE'",
			action:     PolicyActionDeny,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Delete,
				},
			},
			expectAllow: false,
			expectError: false,
		},
		{
			name:       "deny action with non-matching policy",
			expression: "operation == 'DELETE'",
			action:     PolicyActionDeny,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true, // policy doesn't match, so allow
			expectError: false,
		},
		{
			name:       "expression with name variable",
			expression: "name == 'test-pod'",
			action:     PolicyActionDeny,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Name:      "test-pod",
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectError: false,
		},
		{
			name:       "expression with namespace variable",
			expression: "requestNamespace == 'production'",
			action:     PolicyActionDeny,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Namespace: "production",
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectError: false,
		},
		{
			name:       "expression with object variable",
			expression: "has(object.metadata) && object.metadata.name == 'test-pod'",
			action:     PolicyActionDeny,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`),
					},
				},
			},
			expectAllow: false,
			expectError: false,
		},
		{
			name:       "expression with oldObject variable",
			expression: "has(oldObject.metadata) && oldObject.metadata.name == 'test-pod'",
			action:     PolicyActionDeny,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Update,
					OldObject: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`),
					},
				},
			},
			expectAllow: false,
			expectError: false,
		},
		{
			name:       "complex expression with multiple conditions",
			expression: "operation == 'CREATE' && requestNamespace == 'production' && has(object.metadata) && object.metadata.name.startsWith('critical-')",
			action:     PolicyActionDeny,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Namespace: "production",
					Object: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"critical-service"}}`),
					},
				},
			},
			expectAllow: false,
			expectError: false,
		},
		{
			name:       "invalid object JSON",
			expression: "has(object.metadata)",
			action:     PolicyActionAllow,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`invalid json`),
					},
				},
			},
			expectError: true,
			errorMsg:    "unmarshaling object",
		},
		{
			name:       "invalid old object JSON",
			expression: "has(oldObject.metadata)",
			action:     PolicyActionAllow,
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Update,
					OldObject: runtime.RawExtension{
						Raw: []byte(`invalid json`),
					},
				},
			},
			expectError: true,
			errorMsg:    "unmarshaling old object",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &ValidationPolicy{
				Expression: testCase.expression,
				Action:     testCase.action,
			}

			// Provision the policy
			err := policy.Provision(caddy.Context{})
			require.NoError(t, err)

			response, err := policy.Admit(context.Background(), testCase.review)

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, types.UID(uid), response.UID)
			assert.Equal(t, testCase.expectAllow, response.Allowed)
		})
	}
}

func TestValidationPolicy_PolicyActions(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name        string
		action      PolicyAction
		policyMatch bool
		expectAllow bool
	}{
		{
			name:        "allow action with matching policy",
			action:      PolicyActionAllow,
			policyMatch: true,
			expectAllow: true,
		},
		{
			name:        "allow action with non-matching policy",
			action:      PolicyActionAllow,
			policyMatch: false,
			expectAllow: true,
		},
		{
			name:        "deny action with matching policy",
			action:      PolicyActionDeny,
			policyMatch: true,
			expectAllow: false,
		},
		{
			name:        "deny action with non-matching policy",
			action:      PolicyActionDeny,
			policyMatch: false,
			expectAllow: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create expression that either matches or doesn't match based on test case
			expression := "true"
			if !testCase.policyMatch {
				expression = "false"
			}

			policy := &ValidationPolicy{
				Expression: expression,
				Action:     testCase.action,
			}

			err := policy.Provision(caddy.Context{})
			require.NoError(t, err)

			review := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			}

			response, err := policy.Admit(context.Background(), review)

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, testCase.expectAllow, response.Allowed)
		})
	}
}

func TestValidationPolicy_ContextCancellation(t *testing.T) {
	policy := &ValidationPolicy{
		Expression: "true",
		Action:     PolicyActionAllow,
	}

	err := policy.Provision(caddy.Context{})
	require.NoError(t, err)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid"),
			Operation: admissionv1.Create,
		},
	}

	response, err := policy.Admit(ctx, review)

	// The CEL evaluation should handle context cancellation
	// In this simple case, it might still succeed because the expression is trivial
	// But we test that it doesn't panic and returns a proper response or error
	if err != nil {
		assert.Contains(t, err.Error(), "context")
	} else {
		assert.NotNil(t, response)
	}
}

func TestValidationPolicy_IntegrationExample(t *testing.T) {
	// This test demonstrates practical usage of ValidationPolicy
	uid := "integration-test-uid"

	testCases := []struct {
		name          string
		policy        ValidationPolicy
		request       admissionv1.AdmissionRequest
		expectAllowed bool
		description   string
	}{
		{
			name: "deny pods in kube-system namespace",
			policy: ValidationPolicy{
				Expression: "requestNamespace == 'kube-system'",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Create,
				Namespace: "kube-system",
				Object: runtime.RawExtension{
					Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"system-pod","namespace":"kube-system"}}`),
				},
			},
			expectAllowed: false,
			description:   "Should deny pods created in kube-system namespace",
		},
		{
			name: "allow pods in regular namespace",
			policy: ValidationPolicy{
				Expression: "requestNamespace == 'kube-system'",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Create,
				Namespace: "default",
				Object: runtime.RawExtension{
					Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"user-pod","namespace":"default"}}`),
				},
			},
			expectAllowed: true,
			description:   "Should allow pods in regular namespaces",
		},
		{
			name: "enforce naming convention",
			policy: ValidationPolicy{
				Expression: "!name.startsWith('prod-')",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Create,
				Name:      "test-pod",
				Object: runtime.RawExtension{
					Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`),
				},
			},
			expectAllowed: false,
			description:   "Should deny pods that don't follow naming convention",
		},
		{
			name: "allow pods with correct naming",
			policy: ValidationPolicy{
				Expression: "!name.startsWith('prod-')",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Create,
				Name:      "prod-service",
				Object: runtime.RawExtension{
					Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"prod-service"}}`),
				},
			},
			expectAllowed: true,
			description:   "Should allow pods that follow naming convention",
		},
		{
			name: "block critical operations in production",
			policy: ValidationPolicy{
				Expression: "operation == 'DELETE' && requestNamespace == 'production' && has(object.metadata.labels) && 'critical' in object.metadata.labels",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Delete,
				Namespace: "production",
				Object: runtime.RawExtension{
					Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"critical-db","labels":{"critical":"true"}}}`),
				},
			},
			expectAllowed: false,
			description:   "Should deny deletion of critical resources in production",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Provision the policy
			err := testCase.policy.Provision(caddy.Context{})
			require.NoError(t, err, "Failed to provision policy")

			// Create admission review
			review := admissionv1.AdmissionReview{
				Request: &testCase.request,
			}

			// Execute admission review
			response, err := testCase.policy.Admit(context.Background(), review)

			require.NoError(t, err, "Admission review failed")
			require.NotNil(t, response, "Response should not be nil")
			assert.Equal(t, types.UID(uid), response.UID, "UID should match")
			assert.Equal(t, testCase.expectAllowed, response.Allowed, testCase.description)

			t.Logf("Policy result: %v (expected: %v) - %s", response.Allowed, testCase.expectAllowed, testCase.description)
		})
	}
}

func TestJSONPatch_Validate(t *testing.T) {
	testCases := []struct {
		name        string
		patch       JSONPatch
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid add operation",
			patch: JSONPatch{
				Op:    "add",
				Path:  "/metadata/labels/test",
				Value: "test-value",
			},
			expectError: false,
		},
		{
			name: "valid remove operation",
			patch: JSONPatch{
				Op:   "remove",
				Path: "/metadata/labels/test",
			},
			expectError: false,
		},
		{
			name: "valid replace operation",
			patch: JSONPatch{
				Op:    "replace",
				Path:  "/spec/replicas",
				Value: 3,
			},
			expectError: false,
		},
		{
			name: "valid move operation",
			patch: JSONPatch{
				Op:   "move",
				Path: "/metadata/labels/new-label",
				From: "/metadata/labels/old-label",
			},
			expectError: false,
		},
		{
			name: "valid copy operation",
			patch: JSONPatch{
				Op:   "copy",
				Path: "/metadata/labels/copied-label",
				From: "/metadata/labels/source-label",
			},
			expectError: false,
		},
		{
			name: "valid test operation",
			patch: JSONPatch{
				Op:    "test",
				Path:  "/metadata/name",
				Value: "expected-name",
			},
			expectError: false,
		},
		{
			name: "missing operation",
			patch: JSONPatch{
				Path:  "/metadata/labels/test",
				Value: "test-value",
			},
			expectError: true,
			errorMsg:    "operation is required",
		},
		{
			name: "invalid operation",
			patch: JSONPatch{
				Op:    "invalid",
				Path:  "/metadata/labels/test",
				Value: "test-value",
			},
			expectError: true,
			errorMsg:    "invalid operation 'invalid'",
		},
		{
			name: "missing path",
			patch: JSONPatch{
				Op:    "add",
				Value: "test-value",
			},
			expectError: true,
			errorMsg:    "path is required",
		},
		{
			name: "add operation missing value",
			patch: JSONPatch{
				Op:   "add",
				Path: "/metadata/labels/test",
			},
			expectError: true,
			errorMsg:    "'value' field is required for add operation",
		},
		{
			name: "replace operation missing value",
			patch: JSONPatch{
				Op:   "replace",
				Path: "/spec/replicas",
			},
			expectError: true,
			errorMsg:    "'value' field is required for replace operation",
		},
		{
			name: "test operation missing value",
			patch: JSONPatch{
				Op:   "test",
				Path: "/metadata/name",
			},
			expectError: true,
			errorMsg:    "'value' field is required for test operation",
		},
		{
			name: "move operation missing from",
			patch: JSONPatch{
				Op:   "move",
				Path: "/metadata/labels/new-label",
			},
			expectError: true,
			errorMsg:    "'from' field is required for move operation",
		},
		{
			name: "copy operation missing from",
			patch: JSONPatch{
				Op:   "copy",
				Path: "/metadata/labels/copied-label",
			},
			expectError: true,
			errorMsg:    "'from' field is required for copy operation",
		},
		{
			name: "remove operation with value (allowed)",
			patch: JSONPatch{
				Op:    "remove",
				Path:  "/metadata/labels/test",
				Value: "ignored-value",
			},
			expectError: false,
		},
		{
			name: "valid operation with complex value",
			patch: JSONPatch{
				Op:   "add",
				Path: "/spec/template/spec/containers/0/env/-",
				Value: map[string]any{
					"name":  "TEST_ENV",
					"value": "test-value",
				},
			},
			expectError: false,
		},
		{
			name: "valid operation with array value",
			patch: JSONPatch{
				Op:    "replace",
				Path:  "/spec/template/spec/containers/0/ports",
				Value: []any{8080, 8443},
			},
			expectError: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.patch.Validate()

			if testCase.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if testCase.errorMsg != "" && err.Error() != testCase.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", testCase.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestJSONPatchController_Validate(t *testing.T) {
	testCases := []struct {
		name        string
		patches     []JSONPatch
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty patches",
			patches:     []JSONPatch{},
			expectError: false,
		},
		{
			name: "valid patches",
			patches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/metadata/labels/test",
					Value: "test-value",
				},
				{
					Op:   "remove",
					Path: "/metadata/annotations/old-annotation",
				},
			},
			expectError: false,
		},
		{
			name: "first patch invalid",
			patches: []JSONPatch{
				{
					Op:   "add",
					Path: "/metadata/labels/test",
					// Missing value
				},
				{
					Op:   "remove",
					Path: "/metadata/annotations/old-annotation",
				},
			},
			expectError: true,
			errorMsg:    "patch 0: 'value' field is required for add operation",
		},
		{
			name: "second patch invalid",
			patches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/metadata/labels/test",
					Value: "test-value",
				},
				{
					Op:   "move",
					Path: "/metadata/labels/new-label",
					// Missing from
				},
			},
			expectError: true,
			errorMsg:    "patch 1: 'from' field is required for move operation",
		},
		{
			name: "multiple invalid patches - reports all errors",
			patches: []JSONPatch{
				{
					Op:    "invalid-op",
					Path:  "/metadata/labels/test",
					Value: "test-value",
				},
				{
					Path:  "/metadata/labels/test2",
					Value: "test-value2",
					// Missing op
				},
			},
			expectError: true,
			errorMsg:    "patch 0: invalid operation 'invalid-op'\npatch 1: operation is required",
		},
		{
			name: "comprehensive multiple errors",
			patches: []JSONPatch{
				{
					Op:    "invalid-op",
					Path:  "/metadata/labels/test",
					Value: "test-value",
				},
				{
					// Missing op
					Path:  "/metadata/labels/test2",
					Value: "test-value2",
				},
				{
					Op: "add",
					// Missing path
					Value: "test-value3",
				},
				{
					Op:   "move",
					Path: "/metadata/labels/new-label",
					// Missing from
				},
			},
			expectError: true,
			errorMsg:    "patch 0: invalid operation 'invalid-op'\npatch 1: operation is required\npatch 2: path is required\npatch 3: 'from' field is required for move operation",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			controller := &JSONPatcher{
				Patches: testCase.patches,
			}

			err := controller.Validate()

			if testCase.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if testCase.errorMsg != "" && err.Error() != testCase.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", testCase.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestJSONPatchController_Validate_ErrorJoining(t *testing.T) {
	// This test specifically demonstrates the error joining behavior
	controller := &JSONPatcher{
		Patches: []JSONPatch{
			{
				Op:    "invalid-op",
				Path:  "/metadata/labels/test",
				Value: "test-value",
			},
			{
				// Missing op
				Path:  "/metadata/labels/test2",
				Value: "test-value2",
			},
			{
				Op: "add",
				// Missing path
				Value: "test-value3",
			},
		},
	}

	err := controller.Validate()
	require.Error(t, err)

	// Check that all errors are present in the joined error
	errorStr := err.Error()
	assert.Contains(t, errorStr, "patch 0: invalid operation 'invalid-op'")
	assert.Contains(t, errorStr, "patch 1: operation is required")
	assert.Contains(t, errorStr, "patch 2: path is required")

	// Check that errors.Join was used (multiple errors separated by newlines)
	lines := strings.Split(errorStr, "\n")
	assert.Equal(t, 3, len(lines), "Expected 3 error lines")
}

func TestJSONPatchController_UnmarshalCaddyfile_Enhanced(t *testing.T) {
	testCases := []struct {
		name            string
		input           string
		expectedPatches []JSONPatch
		expectError     bool
		errorMsg        string
	}{
		{
			name: "single patch with simple values",
			input: `json_patch {
				patch {
					op add
					path "/metadata/labels/app"
					value "my-app"
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/metadata/labels/app",
					Value: "my-app",
				},
			},
			expectError: false,
		},
		{
			name: "patch with escaped JSON pointer path",
			input: `json_patch {
				patch {
					op add
					path "/metadata/annotations/example.com/special~key"
					value "escaped-value"
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/metadata/annotations/example.com/special~key",
					Value: "escaped-value",
				},
			},
			expectError: false,
		},
		{
			name: "patch with JSON object value",
			input: `json_patch {
				patch {
					op add
					path "/spec/template/spec/containers/0/env/-"
					value {"name":"TEST_ENV","value":"test"}
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:   "add",
					Path: "/spec/template/spec/containers/0/env/-",
					Value: map[string]any{
						"name":  "TEST_ENV",
						"value": "test",
					},
				},
			},
			expectError: false,
		},
		{
			name: "patch with array value using multiple arguments",
			input: `json_patch {
				patch {
					op replace
					path "/spec/template/spec/containers/0/ports"
					value 8080 8443 9090
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:    "replace",
					Path:  "/spec/template/spec/containers/0/ports",
					Value: []any{float64(8080), float64(8443), float64(9090)},
				},
			},
			expectError: false,
		},
		{
			name: "patch with mixed array values",
			input: `json_patch {
				patch {
					op add
					path "/metadata/labels"
					value "string" 42 true {"key":"value"}
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:   "add",
					Path: "/metadata/labels",
					Value: []any{
						"string",
						float64(42),
						true,
						map[string]any{"key": "value"},
					},
				},
			},
			expectError: false,
		},
		{
			name: "move operation with escaped paths",
			input: `json_patch {
				patch {
					op move
					path "/metadata/labels/new~label"
					from "/metadata/labels/old/label"
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:   "move",
					Path: "/metadata/labels/new~label",
					From: "/metadata/labels/old/label",
				},
			},
			expectError: false,
		},
		{
			name: "multiple patches",
			input: `json_patch {
				patch {
					op add
					path "/metadata/labels/app"
					value "my-app"
				}
				patch {
					op remove
					path "/metadata/annotations/old-annotation"
				}
				patch {
					op replace
					path "/spec/replicas"
					value 3
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/metadata/labels/app",
					Value: "my-app",
				},
				{
					Op:   "remove",
					Path: "/metadata/annotations/old-annotation",
				},
				{
					Op:    "replace",
					Path:  "/spec/replicas",
					Value: float64(3),
				},
			},
			expectError: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			controller := &JSONPatcher{}
			d := caddyfile.NewTestDispenser(testCase.input)
			d.Next() // advance to the directive name

			err := controller.UnmarshalCaddyfile(d)

			if testCase.expectError {
				require.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(testCase.expectedPatches), len(controller.Patches))

				for i, expectedPatch := range testCase.expectedPatches {
					if i < len(controller.Patches) {
						actualPatch := controller.Patches[i]
						assert.Equal(t, expectedPatch.Op, actualPatch.Op, "Operation mismatch at patch %d", i)
						assert.Equal(t, expectedPatch.Path, actualPatch.Path, "Path mismatch at patch %d", i)
						assert.Equal(t, expectedPatch.From, actualPatch.From, "From mismatch at patch %d", i)
						assert.Equal(t, expectedPatch.Value, actualPatch.Value, "Value mismatch at patch %d", i)
					}
				}
			}
		})
	}
}

func TestJSONPatchController_Admit(t *testing.T) {
	testCases := []struct {
		name        string
		patches     []JSONPatch
		expectAllow bool
		expectPatch bool
	}{
		{
			name:        "no patches configured",
			patches:     []JSONPatch{},
			expectAllow: true,
			expectPatch: false,
		},
		{
			name: "single patch",
			patches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/metadata/labels/app",
					Value: "my-app",
				},
			},
			expectAllow: true,
			expectPatch: true,
		},
		{
			name: "multiple patches",
			patches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/metadata/labels/app",
					Value: "my-app",
				},
				{
					Op:    "replace",
					Path:  "/spec/replicas",
					Value: 3,
				},
			},
			expectAllow: true,
			expectPatch: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			controller := &JSONPatcher{
				Patches: testCase.patches,
			}

			review := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: "test-uid",
					Object: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`),
					},
				},
			}

			response, err := controller.Admit(context.Background(), review)
			require.NoError(t, err)
			require.NotNil(t, response)

			assert.Equal(t, types.UID("test-uid"), response.UID)
			assert.Equal(t, testCase.expectAllow, response.Allowed)

			if testCase.expectPatch {
				assert.NotNil(t, response.Patch)
				assert.NotNil(t, response.PatchType)
				assert.Equal(t, admissionv1.PatchTypeJSONPatch, *response.PatchType)

				// Verify patch is valid JSON
				var patches []JSONPatch
				err := json.Unmarshal(response.Patch, &patches)
				require.NoError(t, err)
				assert.Equal(t, len(testCase.patches), len(patches))
			} else {
				assert.Nil(t, response.Patch)
				assert.Nil(t, response.PatchType)
			}
		})
	}
}
