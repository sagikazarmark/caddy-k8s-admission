package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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
			name:     "CelPolicy",
			moduleID: "k8s.admission.cel_policy",
			module:   &CelPolicy{},
		},
		{
			name:     "JSONPatch",
			moduleID: "k8s.admission.json_patch",
			module:   &JSONPatch{},
		},
		{
			name:     "JSONPatches",
			moduleID: "k8s.admission.json_patches",
			module:   &JSONPatches{},
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

func TestCelPolicy_CaddyModule(t *testing.T) {
	policy := CelPolicy{}
	moduleInfo := policy.CaddyModule()

	assert.Equal(t, caddy.ModuleID("k8s.admission.cel_policy"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(CelPolicy),
		moduleInfo.New(),
		"Module constructor should return CelPolicy instance",
	)
}

func TestCelPolicy_Provision(t *testing.T) {
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
			policy := &CelPolicy{
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

func TestCelPolicy_ProvisionWithMessage(t *testing.T) {
	testCases := []struct {
		name        string
		expression  string
		action      PolicyAction
		message     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid deny action with message",
			expression:  "operation == 'CREATE'",
			action:      PolicyActionDeny,
			message:     "'Operation ' + operation + ' is not allowed'",
			expectError: false,
		},
		{
			name:        "deny action with complex message expression",
			expression:  "true",
			action:      PolicyActionDeny,
			message:     "has(object.kind) ? 'Cannot create ' + object.kind + ' resources' : 'Cannot create unknown resource'",
			expectError: false,
		},
		{
			name:        "invalid: allow action with message",
			expression:  "true",
			action:      PolicyActionAllow,
			message:     "'This should not be allowed'",
			expectError: true,
			errorMsg:    "message cannot be specified when action is 'allow'",
		},
		{
			name:        "invalid message expression syntax",
			expression:  "true",
			action:      PolicyActionDeny,
			message:     "operation +",
			expectError: true,
			errorMsg:    "compile CEL message expression",
		},
		{
			name:        "message expression returning non-string",
			expression:  "true",
			action:      PolicyActionDeny,
			message:     "true",
			expectError: true,
			errorMsg:    "message expression must return string",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &CelPolicy{
				Expression: testCase.expression,
				Action:     testCase.action,
				Message:    testCase.message,
			}

			err := policy.Provision(caddy.Context{})

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, policy.program)
				if testCase.message != "" {
					assert.NotNil(t, policy.messageProgram)
				}
			}
		})
	}
}

func TestCelPolicy_UnmarshalCaddyfile(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedExpr   string
		expectedAction PolicyAction
		expectedMsg    string
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "valid policy with allow action",
			input: `cel_policy {
				expression "name == 'allowed-pod'"
				action allow
			}`,
			expectedExpr:   "name == 'allowed-pod'",
			expectedAction: PolicyActionAllow,
			expectError:    false,
		},
		{
			name: "valid policy with deny action",
			input: `cel_policy {
				expression "operation == 'DELETE'"
				action deny
			}`,
			expectedExpr:   "operation == 'DELETE'",
			expectedAction: PolicyActionDeny,
			expectError:    false,
		},
		{
			name: "valid policy with message",
			input: `cel_policy {
				expression "operation == 'CREATE'"
				action deny
				message "'Operation ' + operation + ' is not allowed'"
			}`,
			expectedExpr:   "operation == 'CREATE'",
			expectedAction: PolicyActionDeny,
			expectedMsg:    "'Operation ' + operation + ' is not allowed'",
			expectError:    false,
		},
		{
			name: "invalid action",
			input: `cel_policy {
				expression "true"
				action invalid
			}`,
			expectError:    true,
			expectedErrMsg: "invalid action 'invalid'",
		},
		{
			name: "unknown directive",
			input: `cel_policy {
				unknown_directive value
			}`,
			expectError:    true,
			expectedErrMsg: "unknown directive: unknown_directive",
		},
		{
			name: "missing expression argument",
			input: `cel_policy {
				expression
			}`,
			expectError: true,
		},
		{
			name: "missing action argument",
			input: `cel_policy {
				action
			}`,
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &CelPolicy{}
			d := caddyfile.NewTestDispenser(testCase.input)

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
				if testCase.expectedMsg != "" {
					assert.Equal(t, testCase.expectedMsg, policy.Message)
				}
			}
		})
	}
}

func TestCelPolicy_Admit(t *testing.T) {
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
						Raw: []byte(
							`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`,
						),
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
						Raw: []byte(
							`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`,
						),
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
						Raw: []byte(
							`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"critical-service"}}`,
						),
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
			policy := &CelPolicy{
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

func TestCelPolicy_AdmitWithMessage(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name        string
		expression  string
		action      PolicyAction
		message     string
		review      admissionv1.AdmissionReview
		expectAllow bool
		expectError bool
		expectedMsg string
	}{
		{
			name:       "deny action with message - policy matches",
			expression: "operation == 'CREATE'",
			action:     PolicyActionDeny,
			message:    "'CREATE operations are not allowed for ' + (has(object.kind) ? object.kind : 'unknown') + ' resources'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{"kind": "Pod", "metadata": {"name": "test-pod"}}`),
					},
				},
			},
			expectAllow: false,
			expectError: false,
			expectedMsg: "CREATE operations are not allowed for Pod resources",
		},
		{
			name:       "deny action with message - policy doesn't match",
			expression: "operation == 'DELETE'",
			action:     PolicyActionDeny,
			message:    "'DELETE operations are not allowed'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true, // policy doesn't match, so allow
			expectError: false,
			expectedMsg: "", // no message when allowed
		},
		{
			name:       "deny action with complex message expression",
			expression: "true",
			action:     PolicyActionDeny,
			message:    "name != '' ? 'Resource ' + name + ' is not allowed' : 'Unnamed resource is not allowed'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Name:      "test-resource",
				},
			},
			expectAllow: false,
			expectError: false,
			expectedMsg: "Resource test-resource is not allowed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &CelPolicy{
				Expression: testCase.expression,
				Action:     testCase.action,
				Message:    testCase.message,
			}

			// Provision the policy
			err := policy.Provision(caddy.Context{})
			require.NoError(t, err)

			// Call Admit
			response, err := policy.Admit(context.Background(), testCase.review)

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, testCase.review.Request.UID, response.UID)
				assert.Equal(t, testCase.expectAllow, response.Allowed)

				if testCase.expectedMsg != "" {
					require.NotNil(t, response.Result, "Expected result with message")
					assert.Equal(t, testCase.expectedMsg, response.Result.Message)
				} else {
					assert.Nil(t, response.Result, "Expected no result when no message")
				}
			}
		})
	}
}

func TestCelPolicy_PolicyActions(t *testing.T) {
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

			policy := &CelPolicy{
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

func TestCelPolicy_UnmarshalCaddyfileWithName(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedName   string
		expectedExpr   string
		expectedAction PolicyAction
		expectedMsg    string
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "name as argument",
			input: `cel_policy my_policy {
				expression "name == 'allowed-pod'"
				action allow
			}`,
			expectedName:   "my_policy",
			expectedExpr:   "name == 'allowed-pod'",
			expectedAction: PolicyActionAllow,
			expectError:    false,
		},
		{
			name: "name as directive",
			input: `cel_policy {
				name my_policy
				expression "operation == 'DELETE'"
				action deny
			}`,
			expectedName:   "my_policy",
			expectedExpr:   "operation == 'DELETE'",
			expectedAction: PolicyActionDeny,
			expectError:    false,
		},
		{
			name: "name as directive overrides argument",
			input: `cel_policy argument_name {
				name directive_name
				expression "true"
				action allow
			}`,
			expectedName:   "directive_name",
			expectedExpr:   "true",
			expectedAction: PolicyActionAllow,
			expectError:    false,
		},
		{
			name: "name with message",
			input: `cel_policy test_policy {
				expression "operation == 'CREATE'"
				action deny
				message "'Custom message from ' + policyName"
			}`,
			expectedName:   "test_policy",
			expectedExpr:   "operation == 'CREATE'",
			expectedAction: PolicyActionDeny,
			expectedMsg:    "'Custom message from ' + policyName",
			expectError:    false,
		},
		{
			name: "missing name argument",
			input: `cel_policy {
				name
			}`,
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &CelPolicy{}
			d := caddyfile.NewTestDispenser(testCase.input)

			err := policy.UnmarshalCaddyfile(d)

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), testCase.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.expectedName, policy.Name)
				assert.Equal(t, testCase.expectedExpr, policy.Expression)
				assert.Equal(t, testCase.expectedAction, policy.Action)
				if testCase.expectedMsg != "" {
					assert.Equal(t, testCase.expectedMsg, policy.Message)
				}
			}
		})
	}
}

func TestCelPolicy_AdmitWithName(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name        string
		policyName  string
		expression  string
		action      PolicyAction
		message     string
		review      admissionv1.AdmissionReview
		expectAllow bool
		expectError bool
		expectedMsg string
	}{
		{
			name:       "deny with name only - uses fallback message",
			policyName: "test_policy",
			expression: "operation == 'CREATE'",
			action:     PolicyActionDeny,
			message:    "", // no custom message
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectError: false,
			expectedMsg: "Rejected by 'test_policy' policy",
		},
		{
			name:       "deny with custom message overrides fallback",
			policyName: "test_policy",
			expression: "operation == 'CREATE'",
			action:     PolicyActionDeny,
			message:    "'Custom denial message'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectError: false,
			expectedMsg: "Custom denial message",
		},
		{
			name:       "deny with no name and no message - no status",
			policyName: "", // no name
			expression: "operation == 'CREATE'",
			action:     PolicyActionDeny,
			message:    "", // no message
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectError: false,
			expectedMsg: "", // no message should be set
		},
		{
			name:       "allow with name - no message",
			policyName: "test_policy",
			expression: "operation == 'CREATE'",
			action:     PolicyActionAllow,
			message:    "",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
			expectError: false,
			expectedMsg: "", // no message when allowing
		},
		{
			name:       "policy doesn't match - allow with no message",
			policyName: "test_policy",
			expression: "operation == 'DELETE'",
			action:     PolicyActionDeny,
			message:    "",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true, // policy doesn't match, so allow
			expectError: false,
			expectedMsg: "", // no message when allowing
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &CelPolicy{
				Name:       testCase.policyName,
				Expression: testCase.expression,
				Action:     testCase.action,
				Message:    testCase.message,
			}

			// Provision the policy
			err := policy.Provision(caddy.Context{})
			require.NoError(t, err)

			// Call Admit
			response, err := policy.Admit(context.Background(), testCase.review)

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, testCase.review.Request.UID, response.UID)
				assert.Equal(t, testCase.expectAllow, response.Allowed)

				if testCase.expectedMsg != "" {
					require.NotNil(t, response.Result, "Expected result with message")
					assert.Equal(t, testCase.expectedMsg, response.Result.Message)
				} else {
					assert.Nil(t, response.Result, "Expected no result when no message")
				}
			}
		})
	}
}

func TestCelPolicy_PolicyNameInCEL(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name        string
		policyName  string
		expression  string
		action      PolicyAction
		message     string
		review      admissionv1.AdmissionReview
		expectAllow bool
		expectError bool
		expectedMsg string
	}{
		{
			name:       "use policyName in expression",
			policyName: "security_policy",
			expression: "policyName == 'security_policy'",
			action:     PolicyActionAllow,
			message:    "",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
			expectError: false,
			expectedMsg: "",
		},
		{
			name:       "use policyName in message expression",
			policyName: "validation_policy",
			expression: "operation == 'CREATE'",
			action:     PolicyActionDeny,
			message:    "'Request denied by policy: ' + policyName",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectError: false,
			expectedMsg: "Request denied by policy: validation_policy",
		},
		{
			name:       "policyName is empty string when name is not set",
			policyName: "", // no policy name
			expression: "policyName == ''",
			action:     PolicyActionAllow,
			message:    "",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
			expectError: false,
			expectedMsg: "",
		},
		{
			name:       "complex expression with policyName",
			policyName: "resource_policy",
			expression: "policyName == 'resource_policy' && operation == 'CREATE' && has(object.metadata) && has(object.metadata.labels) && has(object.metadata.labels.restricted)",
			action:     PolicyActionDeny,
			message:    "policyName + ': Restricted resources cannot be created'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{"apiVersion": "v1", "kind": "Pod", "metadata": {"labels": {"restricted": "true"}}}`),
					},
				},
			},
			expectAllow: false,
			expectError: false,
			expectedMsg: "resource_policy: Restricted resources cannot be created",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &CelPolicy{
				Name:       testCase.policyName,
				Expression: testCase.expression,
				Action:     testCase.action,
				Message:    testCase.message,
			}

			// Provision the policy
			err := policy.Provision(caddy.Context{})
			require.NoError(t, err)

			// Call Admit
			response, err := policy.Admit(context.Background(), testCase.review)

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, testCase.review.Request.UID, response.UID)
				assert.Equal(t, testCase.expectAllow, response.Allowed)

				if testCase.expectedMsg != "" {
					require.NotNil(t, response.Result, "Expected result with message")
					assert.Equal(t, testCase.expectedMsg, response.Result.Message)
				} else {
					assert.Nil(t, response.Result, "Expected no result when no message")
				}
			}
		})
	}
}

func TestCelPolicy_MessageFallbackBehavior(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name            string
		policyName      string
		message         string
		expectStatusSet bool
		expectedMessage string
		description     string
	}{
		{
			name:            "name set, no message - fallback message",
			policyName:      "security_check",
			message:         "",
			expectStatusSet: true,
			expectedMessage: "Rejected by 'security_check' policy",
			description:     "Should use fallback message when name is set but message is empty",
		},
		{
			name:            "name set, message set - custom message",
			policyName:      "security_check",
			message:         "'Custom rejection message'",
			expectStatusSet: true,
			expectedMessage: "Custom rejection message",
			description:     "Should use custom message when both name and message are set",
		},
		{
			name:            "no name, message set - custom message",
			policyName:      "",
			message:         "'Message without policy name'",
			expectStatusSet: true,
			expectedMessage: "Message without policy name",
			description:     "Should use custom message when name is empty but message is set",
		},
		{
			name:            "no name, no message - no status",
			policyName:      "",
			message:         "",
			expectStatusSet: false,
			expectedMessage: "",
			description:     "Should not set any status when both name and message are empty",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := &CelPolicy{
				Name:       testCase.policyName,
				Expression: "operation == 'CREATE'", // Always matches CREATE operations
				Action:     PolicyActionDeny,        // Always denies when matched
				Message:    testCase.message,
			}

			// Provision the policy
			err := policy.Provision(caddy.Context{})
			require.NoError(t, err)

			// Create a review that will match the policy (CREATE operation)
			review := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			}

			// Call Admit
			response, err := policy.Admit(context.Background(), review)

			// Verify basic response
			assert.NoError(t, err, testCase.description)
			assert.NotNil(t, response, testCase.description)
			assert.Equal(t, types.UID(uid), response.UID, testCase.description)
			assert.False(t, response.Allowed, "All test cases should deny the request: %s", testCase.description)

			// Verify message behavior
			if testCase.expectStatusSet {
				require.NotNil(t, response.Result, "Expected status to be set: %s", testCase.description)
				assert.Equal(t, testCase.expectedMessage, response.Result.Message, testCase.description)
			} else {
				assert.Nil(t, response.Result, "Expected no status to be set: %s", testCase.description)
			}
		})
	}
}

func TestCelPolicy_ContextCancellation(t *testing.T) {
	policy := &CelPolicy{
		Expression: "true",
		Action:     PolicyActionAllow,
	}

	err := policy.Provision(caddy.Context{})
	require.NoError(t, err)

	// Create a canceled context
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

func TestCelPolicy_IntegrationExample(t *testing.T) {
	// This test demonstrates practical usage of CelPolicy
	uid := "integration-test-uid"

	testCases := []struct {
		name          string
		policy        CelPolicy
		request       admissionv1.AdmissionRequest
		expectAllowed bool
		description   string
	}{
		{
			name: "deny pods in kube-system namespace",
			policy: CelPolicy{
				Expression: "requestNamespace == 'kube-system'",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Create,
				Namespace: "kube-system",
				Object: runtime.RawExtension{
					Raw: []byte(
						`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"system-pod","namespace":"kube-system"}}`,
					),
				},
			},
			expectAllowed: false,
			description:   "Should deny pods created in kube-system namespace",
		},
		{
			name: "allow pods in regular namespace",
			policy: CelPolicy{
				Expression: "requestNamespace == 'kube-system'",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Create,
				Namespace: "default",
				Object: runtime.RawExtension{
					Raw: []byte(
						`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"user-pod","namespace":"default"}}`,
					),
				},
			},
			expectAllowed: true,
			description:   "Should allow pods in regular namespaces",
		},
		{
			name: "enforce naming convention",
			policy: CelPolicy{
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
			policy: CelPolicy{
				Expression: "!name.startsWith('prod-')",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Create,
				Name:      "prod-service",
				Object: runtime.RawExtension{
					Raw: []byte(
						`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"prod-service"}}`,
					),
				},
			},
			expectAllowed: true,
			description:   "Should allow pods that follow naming convention",
		},
		{
			name: "block critical operations in production",
			policy: CelPolicy{
				Expression: "operation == 'DELETE' && requestNamespace == 'production' && has(object.metadata.labels) && 'critical' in object.metadata.labels",
				Action:     PolicyActionDeny,
			},
			request: admissionv1.AdmissionRequest{
				UID:       types.UID(uid),
				Operation: admissionv1.Delete,
				Namespace: "production",
				Object: runtime.RawExtension{
					Raw: []byte(
						`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"critical-db","labels":{"critical":"true"}}}`,
					),
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

			t.Logf(
				"Policy result: %v (expected: %v) - %s",
				response.Allowed,
				testCase.expectAllowed,
				testCase.description,
			)
		})
	}
}

func TestJSONPatch_CaddyModule(t *testing.T) {
	// Test that the JSONPatch properly implements Caddy module interface
	module := JSONPatch{}
	moduleInfo := module.CaddyModule()

	assert.Equal(t, caddy.ModuleID("k8s.admission.json_patch"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(JSONPatch),
		moduleInfo.New(),
		"Module constructor should return JSONPatch instance",
	)
}

func TestJSONPatch_UnmarshalCaddyfile(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedOp    string
		expectedPath  string
		expectedValue any
		expectedFrom  string
		expectError   bool
		errorMsg      string
	}{
		{
			name: "simple add operation",
			input: `json_patch {
				op add
				path "/metadata/labels/test"
				value "test-value"
			}`,
			expectedOp:    "add",
			expectedPath:  "/metadata/labels/test",
			expectedValue: "test-value",
		},
		{
			name: "remove operation",
			input: `json_patch {
				op remove
				path "/metadata/annotations/unwanted"
			}`,
			expectedOp:   "remove",
			expectedPath: "/metadata/annotations/unwanted",
		},
		{
			name: "replace operation with number",
			input: `json_patch {
				op replace
				path "/spec/replicas"
				value 3
			}`,
			expectedOp:    "replace",
			expectedPath:  "/spec/replicas",
			expectedValue: float64(3), // JSON numbers are parsed as float64
		},
		{
			name: "move operation",
			input: `json_patch {
				op move
				path "/metadata/labels/new-label"
				from "/metadata/labels/old-label"
			}`,
			expectedOp:   "move",
			expectedPath: "/metadata/labels/new-label",
			expectedFrom: "/metadata/labels/old-label",
		},
		{
			name: "array values",
			input: `json_patch {
				op add
				path "/spec/ports"
				value 8080 8443 9090
			}`,
			expectedOp:    "add",
			expectedPath:  "/spec/ports",
			expectedValue: []any{float64(8080), float64(8443), float64(9090)},
		},
		{
			name: "JSON object value",
			input: `json_patch {
				op add
				path "/metadata/annotations/config"
				value {"key":"value","nested":{"data":true}}
			}`,
			expectedOp:   "add",
			expectedPath: "/metadata/annotations/config",
			expectedValue: map[string]any{
				"key": "value",
				"nested": map[string]any{
					"data": true,
				},
			},
		},
		{
			name: "unknown directive error",
			input: `json_patch {
				op add
				path "/test"
				unknown_directive
			}`,
			expectError: true,
			errorMsg:    "unknown directive",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(testCase.input)
			patch := &JSONPatch{}

			err := patch.UnmarshalCaddyfile(d)

			if testCase.expectError {
				require.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.expectedOp, patch.Op)
			assert.Equal(t, testCase.expectedPath, patch.Path)
			assert.Equal(t, testCase.expectedFrom, patch.From)

			if testCase.expectedValue != nil {
				assert.Equal(t, testCase.expectedValue, patch.Value)
			}
		})
	}
}

func TestJSONPatch_Admit(t *testing.T) {
	testCases := []struct {
		name        string
		patch       JSONPatch
		expectAllow bool
		expectPatch bool
	}{
		{
			name: "add operation",
			patch: JSONPatch{
				Op:    "add",
				Path:  "/metadata/labels/test",
				Value: "test-value",
			},
			expectAllow: true,
			expectPatch: true,
		},
		{
			name: "remove operation",
			patch: JSONPatch{
				Op:   "remove",
				Path: "/metadata/labels/unwanted",
			},
			expectAllow: true,
			expectPatch: true,
		},
		{
			name: "replace with object",
			patch: JSONPatch{
				Op:   "replace",
				Path: "/spec/template/spec/containers/0/resources",
				Value: map[string]any{
					"limits": map[string]any{
						"memory": "512Mi",
						"cpu":    "500m",
					},
				},
			},
			expectAllow: true,
			expectPatch: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			review := createTestAdmissionReview(t, "CREATE", map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name":      "test-pod",
					"namespace": "default",
				},
			})

			response, err := testCase.patch.Admit(context.Background(), *review)

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, testCase.expectAllow, response.Allowed)
			assert.Equal(t, review.Request.UID, response.UID)

			if testCase.expectPatch {
				require.NotNil(t, response.Patch)
				require.NotNil(t, response.PatchType)
				assert.Equal(t, admissionv1.PatchTypeJSONPatch, *response.PatchType)

				// Verify patch structure
				var patches []JSONPatch
				err := json.Unmarshal(response.Patch, &patches)
				require.NoError(t, err)
				require.Len(t, patches, 1)
				assert.Equal(t, testCase.patch.Op, patches[0].Op)
				assert.Equal(t, testCase.patch.Path, patches[0].Path)
			} else {
				assert.Nil(t, response.Patch)
			}
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
					t.Errorf(
						"expected error message '%s', got '%s'",
						testCase.errorMsg,
						err.Error(),
					)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestJSONPatches_Validate(t *testing.T) {
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
			controller := &JSONPatches{
				Patches: testCase.patches,
			}

			err := controller.Validate()

			if testCase.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if testCase.errorMsg != "" && err.Error() != testCase.errorMsg {
					t.Errorf(
						"expected error message '%s', got '%s'",
						testCase.errorMsg,
						err.Error(),
					)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Helper function to create a test admission review
func createTestAdmissionReview(
	t *testing.T,
	operation string,
	objectData map[string]any,
) *admissionv1.AdmissionReview {
	var obj runtime.RawExtension
	if objectData != nil {
		objJSON, err := json.Marshal(objectData)
		require.NoError(t, err, "Failed to marshal object data")
		obj = runtime.RawExtension{Raw: objJSON}
	}

	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID(fmt.Sprintf("test-uid-%s-%d", operation, time.Now().UnixNano())),
			Operation: admissionv1.Operation(operation),
			Namespace: "default",
			Name:      "test-resource",
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Object: obj,
		},
	}
}

func TestJSONPatches_Validate_ErrorJoining(t *testing.T) {
	// This test specifically demonstrates the error joining behavior
	controller := &JSONPatches{
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

func TestJSONPatches_UnmarshalCaddyfile_Enhanced(t *testing.T) {
	testCases := []struct {
		name            string
		input           string
		expectedPatches []JSONPatch
		expectError     bool
		errorMsg        string
	}{
		{
			name: "single patch with simple values",
			input: `json_patches {
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
			input: `json_patches {
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
			input: `json_patches {
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
			input: `json_patches {
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
			input: `json_patches {
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
			input: `json_patches {
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
			input: `json_patches {
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
			d := caddyfile.NewTestDispenser(testCase.input)
			controller := &JSONPatches{}

			err := controller.UnmarshalCaddyfile(d)

			if testCase.expectError {
				require.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
			} else {
				require.NoError(t, err)

				// Provision to load the modules
				ctx := caddy.Context{Context: context.Background()}
				err = controller.Provision(ctx)
				require.NoError(t, err)

				assert.Equal(t, len(testCase.expectedPatches), len(controller.Patches))

				for i, expectedPatch := range testCase.expectedPatches {
					if i < len(controller.Patches) {
						actualPatch := controller.Patches[i]
						assert.Equal(t, expectedPatch.Op, actualPatch.Op, "Operation mismatch at patch %d", i)
						assert.Equal(t, expectedPatch.Path, actualPatch.Path, "Path mismatch at patch %d", i)
						assert.Equal(t, expectedPatch.Value, actualPatch.Value, "Value mismatch at patch %d", i)
						assert.Equal(t, expectedPatch.From, actualPatch.From, "From mismatch at patch %d", i)
					}
				}
			}
		})
	}
}

func TestJSONPatches_Admit(t *testing.T) {
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
			controller := &JSONPatches{
				Patches: testCase.patches,
			}

			review := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: "test-uid",
					Object: runtime.RawExtension{
						Raw: []byte(
							`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`,
						),
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
