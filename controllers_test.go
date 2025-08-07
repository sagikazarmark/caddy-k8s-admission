package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	// Test that the AlwaysAllow properly implements Caddy module interface
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
	testCases := []struct {
		name   string
		review admissionv1.AdmissionReview
	}{
		{
			name: "simple allow",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: "test-uid",
				},
			},
		},
		{
			name: "allow with operation",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       "test-uid-2",
					Operation: admissionv1.Create,
				},
			},
		},
		{
			name: "allow with complex request",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       "test-uid-3",
					Operation: admissionv1.Update,
					Kind: metav1.GroupVersionKind{
						Group:   "",
						Version: "v1",
						Kind:    "Pod",
					},
					Name:      "test-pod",
					Namespace: "default",
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
			assert.True(t, response.Allowed)
			assert.Equal(t, testCase.review.Request.UID, response.UID)
			assert.Nil(t, response.Result)
			assert.Nil(t, response.Patch)
		})
	}
}

func TestAlwaysDeny_CaddyModule(t *testing.T) {
	// Test that the AlwaysDeny properly implements Caddy module interface
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
	testCases := []struct {
		name   string
		review admissionv1.AdmissionReview
	}{
		{
			name: "simple deny",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: "test-uid",
				},
			},
		},
		{
			name: "deny with operation",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       "test-uid-2",
					Operation: admissionv1.Create,
				},
			},
		},
		{
			name: "deny with complex request",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       "test-uid-3",
					Operation: admissionv1.Update,
					Kind: metav1.GroupVersionKind{
						Group:   "",
						Version: "v1",
						Kind:    "Pod",
					},
					Name:      "test-pod",
					Namespace: "default",
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
			assert.False(t, response.Allowed)
			assert.Equal(t, testCase.review.Request.UID, response.UID)
		})
	}
}

func TestControllersModuleRegistration(t *testing.T) {
	// Test that all controller modules are properly registered
	expectedModules := map[string]caddy.ModuleInfo{
		"always_allow": AlwaysAllow{}.CaddyModule(),
		"always_deny":  AlwaysDeny{}.CaddyModule(),
		"validation":   Validation{}.CaddyModule(),
		"json_patch":   JSONPatch{}.CaddyModule(),
		"json_patches": JSONPatches{}.CaddyModule(),
	}

	for name, expectedInfo := range expectedModules {
		t.Run(name, func(t *testing.T) {
			moduleID := expectedInfo.ID
			module, err := caddy.GetModule(string(moduleID))

			require.NoError(t, err, "Module %s should be registered", moduleID)
			require.NotNil(t, module, "Module %s should be registered", moduleID)
			assert.Equal(t, expectedInfo.ID, module.ID)
			assert.NotNil(t, module.New)

			// Test that we can create an instance
			instance := module.New()
			assert.NotNil(t, instance)

			// Test that instance implements Controller interface
			_, ok := instance.(Controller)
			assert.True(t, ok, "Module should implement Controller interface")
		})
	}
}

func TestValidation_CaddyModule(t *testing.T) {
	// Test that the Validation properly implements Caddy module interface
	module := Validation{}
	moduleInfo := module.CaddyModule()

	assert.Equal(t, caddy.ModuleID("k8s.admission.validation"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(Validation),
		moduleInfo.New(),
		"Module constructor should return Validation instance",
	)
}

func TestValidation_Provision(t *testing.T) {
	testCases := []struct {
		name        string
		expression  string
		reason      ValidationReason
		expectError bool
	}{
		{
			name:       "valid boolean expression",
			expression: "true",
		},
		{
			name:       "valid expression with variables",
			expression: "name == 'test-pod'",
		},
		{
			name:       "valid complex expression",
			expression: "operation == 'CREATE' && has(object.metadata) && object.metadata.name.startsWith('prod-')",
		},
		{
			name:       "valid with custom reason",
			expression: "true",
			reason:     ValidationReasonForbidden,
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
			name:        "invalid reason",
			expression:  "true",
			reason:      ValidationReason("InvalidReason"),
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Expression: testCase.expression,
				Reason:     testCase.reason,
			}

			err := validation.Provision(caddy.Context{})

			if testCase.expectError {
				assert.Error(t, err)
				assert.Nil(t, validation.program)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validation.program)
				// Check default reason is set
				if testCase.reason == "" {
					assert.Equal(t, ValidationReasonInvalid, validation.Reason)
				}
			}
		})
	}
}

func TestValidation_ProvisionWithMessage(t *testing.T) {
	testCases := []struct {
		name              string
		expression        string
		message           string
		messageExpression string
		reason            ValidationReason
		expectError       bool
		errorMsg          string
	}{
		{
			name:       "valid expression with static message",
			expression: "false",
			message:    "Static denial message",
		},
		{
			name:              "valid expression with message expression",
			expression:        "false",
			messageExpression: "'Dynamic message for ' + object.kind",
		},
		{
			name:              "both message and message expression",
			expression:        "false",
			message:           "Static message",
			messageExpression: "'Dynamic message'",
		},
		{
			name:       "valid reason",
			expression: "false",
			reason:     ValidationReasonForbidden,
		},
		{
			name:        "invalid reason",
			expression:  "false",
			reason:      ValidationReason("InvalidReason"),
			expectError: true,
			errorMsg:    "invalid reason",
		},
		{
			name:              "invalid message expression syntax",
			expression:        "false",
			messageExpression: "invalid syntax ==",
			expectError:       true,
			errorMsg:          "compile CEL message expression",
		},
		{
			name:              "message expression returning non-string",
			expression:        "false",
			messageExpression: "42",
			expectError:       true,
			errorMsg:          "message expression must return string",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Expression:        testCase.expression,
				Message:           testCase.message,
				MessageExpression: testCase.messageExpression,
				Reason:            testCase.reason,
			}

			err := validation.Provision(caddy.Context{})

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validation.program)
				if testCase.messageExpression != "" {
					assert.NotNil(t, validation.messageProgram)
				}
			}
		})
	}
}

func TestValidation_UnmarshalCaddyfile(t *testing.T) {
	testCases := []struct {
		name            string
		input           string
		expectedExpr    string
		expectedMsg     string
		expectedMsgExpr string
		expectedReason  ValidationReason
		expectError     bool
		expectedErrMsg  string
	}{
		{
			name: "simple expression",
			input: `validation {
				expression "true"
			}`,
			expectedExpr: "true",
		},
		{
			name: "expression with static message",
			input: `validation {
				expression "false"
				message "Access denied"
			}`,
			expectedExpr: "false",
			expectedMsg:  "Access denied",
		},
		{
			name: "expression with message expression",
			input: `validation {
				expression "false"
				message_expression "'Denied for ' + object.kind"
			}`,
			expectedExpr:    "false",
			expectedMsgExpr: "'Denied for ' + object.kind",
		},
		{
			name: "expression with reason",
			input: `validation {
				expression "false"
				reason Forbidden
			}`,
			expectedExpr:   "false",
			expectedReason: ValidationReasonForbidden,
		},
		{
			name: "complex validation",
			input: `validation {
				name "namespace-policy"
				expression "requestNamespace != 'kube-system'"
				message "kube-system namespace is protected"
				reason Forbidden
			}`,
			expectedExpr:   "requestNamespace != 'kube-system'",
			expectedMsg:    "kube-system namespace is protected",
			expectedReason: ValidationReasonForbidden,
		},
		{
			name: "validation with name as argument",
			input: `validation my-policy {
				expression "true"
			}`,
			expectedExpr: "true",
		},
		{
			name: "invalid reason",
			input: `validation {
				expression "true"
				reason InvalidReason
			}`,
			expectError:    true,
			expectedErrMsg: "invalid reason",
		},
		{
			name: "missing expression",
			input: `validation {
				message "test"
			}`,
			expectedMsg: "test",
		},
		{
			name: "unknown directive",
			input: `validation {
				expression "true"
				unknown_directive
			}`,
			expectError:    true,
			expectedErrMsg: "unknown directive: unknown_directive",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(testCase.input)
			validation := &Validation{}

			err := validation.UnmarshalCaddyfile(d)

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), testCase.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.expectedExpr, validation.Expression)
				assert.Equal(t, testCase.expectedMsg, validation.Message)
				assert.Equal(t, testCase.expectedMsgExpr, validation.MessageExpression)
				if testCase.expectedReason != "" {
					assert.Equal(t, testCase.expectedReason, validation.Reason)
				}
			}
		})
	}
}

func TestValidation_UnmarshalCaddyfileWithName(t *testing.T) {
	testCases := []struct {
		name            string
		input           string
		expectedName    string
		expectedExpr    string
		expectedMsg     string
		expectedMsgExpr string
		expectedReason  ValidationReason
		expectError     bool
		expectedErrMsg  string
	}{
		{
			name: "name as argument",
			input: `validation my-validation {
				expression "true"
			}`,
			expectedName: "my-validation",
			expectedExpr: "true",
		},
		{
			name: "name in block",
			input: `validation {
				name "my-validation"
				expression "true"
			}`,
			expectedName: "my-validation",
			expectedExpr: "true",
		},
		{
			name: "name as argument overrides block name",
			input: `validation arg-name {
				name "block-name"
				expression "true"
			}`,
			expectedName: "block-name", // block directive takes precedence
			expectedExpr: "true",
		},
		{
			name: "full configuration",
			input: `validation comprehensive-policy {
				expression "operation != 'DELETE'"
				message "DELETE operations are not allowed"
				message_expression "'Cannot delete ' + object.kind + ' resources'"
				reason Forbidden
			}`,
			expectedName:    "comprehensive-policy",
			expectedExpr:    "operation != 'DELETE'",
			expectedMsg:     "DELETE operations are not allowed",
			expectedMsgExpr: "'Cannot delete ' + object.kind + ' resources'",
			expectedReason:  ValidationReasonForbidden,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(testCase.input)
			validation := &Validation{}

			err := validation.UnmarshalCaddyfile(d)

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), testCase.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.expectedName, validation.Name)
				assert.Equal(t, testCase.expectedExpr, validation.Expression)
				assert.Equal(t, testCase.expectedMsg, validation.Message)
				assert.Equal(t, testCase.expectedMsgExpr, validation.MessageExpression)
				if testCase.expectedReason != "" {
					assert.Equal(t, testCase.expectedReason, validation.Reason)
				}
			}
		})
	}
}

func TestValidation_Admit(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name        string
		expression  string
		review      admissionv1.AdmissionReview
		expectAllow bool
		expectError bool
		errorMsg    string
	}{
		{
			name:       "expression returns true - allow",
			expression: "true",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
		},
		{
			name:       "expression returns false - deny",
			expression: "false",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
		},
		{
			name:       "operation-based validation - allow UPDATE",
			expression: "operation != 'CREATE'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Update,
				},
			},
			expectAllow: true,
		},
		{
			name:       "operation-based validation - deny CREATE",
			expression: "operation != 'CREATE'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
		},
		{
			name:       "namespace-based validation - allow",
			expression: "requestNamespace != 'kube-system'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Namespace: "default",
				},
			},
			expectAllow: true,
		},
		{
			name:       "namespace-based validation - deny",
			expression: "requestNamespace != 'kube-system'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Namespace: "kube-system",
				},
			},
			expectAllow: false,
		},
		{
			name:       "object-based validation - with object",
			expression: "has(object.metadata) && object.metadata.name.startsWith('test-')",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`),
					},
				},
			},
			expectAllow: true,
		},
		{
			name:       "object-based validation - without required prefix",
			expression: "has(object.metadata) && object.metadata.name.startsWith('prod-')",
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
		},
		{
			name:       "invalid object JSON",
			expression: "has(object.metadata)",
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
			name:       "expression with operation validation",
			expression: "operation != 'CREATE'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Expression: testCase.expression,
			}

			err := validation.Provision(caddy.Context{})
			require.NoError(t, err)

			response, err := validation.Admit(context.Background(), testCase.review)

			if testCase.expectError {
				assert.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, testCase.expectAllow, response.Allowed)
				assert.Equal(t, testCase.review.Request.UID, response.UID)
			}
		})
	}
}

func TestValidation_AdmitWithMessage(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name              string
		expression        string
		message           string
		messageExpression string
		review            admissionv1.AdmissionReview
		expectAllow       bool
		expectError       bool
		expectedMsg       string
	}{
		{
			name:       "denied with static message",
			expression: "false",
			message:    "Static denial message",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectedMsg: "Static denial message",
		},
		{
			name:              "denied with message expression",
			expression:        "false",
			messageExpression: "'Dynamic message for ' + operation + ' operation'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectedMsg: "Dynamic message for CREATE operation",
		},
		{
			name:              "message expression takes precedence",
			expression:        "false",
			message:           "Static message",
			messageExpression: "'Dynamic message wins'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectedMsg: "Dynamic message wins",
		},
		{
			name:       "allowed request has no message",
			expression: "true",
			message:    "This should not appear",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
		},
		{
			name:              "message expression with object data",
			expression:        "false",
			messageExpression: "'Pod ' + object.metadata.name + ' is not allowed'",
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
			expectedMsg: "Pod test-pod is not allowed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Expression:        testCase.expression,
				Message:           testCase.message,
				MessageExpression: testCase.messageExpression,
			}

			err := validation.Provision(caddy.Context{})
			require.NoError(t, err)

			response, err := validation.Admit(context.Background(), testCase.review)

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, testCase.expectAllow, response.Allowed)
				assert.Equal(t, testCase.review.Request.UID, response.UID)

				if !testCase.expectAllow && testCase.expectedMsg != "" {
					require.NotNil(t, response.Result)
					assert.Equal(t, testCase.expectedMsg, response.Result.Message)
				}

				if testCase.expectAllow {
					assert.Nil(t, response.Result)
				}
			}
		})
	}
}

func TestValidation_AdmitWithName(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name              string
		validationName    string
		expression        string
		message           string
		messageExpression string
		review            admissionv1.AdmissionReview
		expectAllow       bool
		expectError       bool
		expectedMsg       string
	}{
		{
			name:           "denied with name fallback message",
			validationName: "test-validation",
			expression:     "false",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectedMsg: "Rejected by 'test-validation' validation",
		},
		{
			name:           "static message overrides name",
			validationName: "test-validation",
			expression:     "false",
			message:        "Custom static message",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectedMsg: "Custom static message",
		},
		{
			name:              "message expression overrides static message and name",
			validationName:    "test-validation",
			expression:        "false",
			message:           "Static message",
			messageExpression: "'Expression message for ' + policyName",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectedMsg: "Expression message for test-validation",
		},
		{
			name:           "allowed request has no message even with name",
			validationName: "test-validation",
			expression:     "true",
			message:        "This should not appear",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Name:              testCase.validationName,
				Expression:        testCase.expression,
				Message:           testCase.message,
				MessageExpression: testCase.messageExpression,
			}

			err := validation.Provision(caddy.Context{})
			require.NoError(t, err)

			response, err := validation.Admit(context.Background(), testCase.review)

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, testCase.expectAllow, response.Allowed)
				assert.Equal(t, testCase.review.Request.UID, response.UID)

				if !testCase.expectAllow && testCase.expectedMsg != "" {
					require.NotNil(t, response.Result)
					assert.Equal(t, testCase.expectedMsg, response.Result.Message)
				}

				if testCase.expectAllow {
					assert.Nil(t, response.Result)
				}
			}
		})
	}
}

func TestValidation_ValidationNameInCEL(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name              string
		validationName    string
		expression        string
		messageExpression string
		review            admissionv1.AdmissionReview
		expectAllow       bool
		expectedMsg       string
	}{
		{
			name:           "policyName available in expression",
			validationName: "my-validation",
			expression:     "policyName == 'my-validation'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: true,
		},
		{
			name:              "policyName in message expression",
			validationName:    "test-validation",
			expression:        "false",
			messageExpression: "'Denied by ' + policyName + ' validation'",
			review: admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			},
			expectAllow: false,
			expectedMsg: "Denied by test-validation validation",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Name:              testCase.validationName,
				Expression:        testCase.expression,
				MessageExpression: testCase.messageExpression,
			}

			err := validation.Provision(caddy.Context{})
			require.NoError(t, err)

			response, err := validation.Admit(context.Background(), testCase.review)

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, testCase.expectAllow, response.Allowed)
			assert.Equal(t, testCase.review.Request.UID, response.UID)

			if !testCase.expectAllow && testCase.expectedMsg != "" {
				require.NotNil(t, response.Result)
				assert.Equal(t, testCase.expectedMsg, response.Result.Message)
			}

			if testCase.expectAllow {
				assert.Nil(t, response.Result)
			}
		})
	}
}

func TestValidation_ReasonMapping(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name             string
		reason           ValidationReason
		expectedHTTPCode int32
		expectedReason   metav1.StatusReason
	}{
		{
			name:             "Unauthorized reason",
			reason:           ValidationReasonUnauthorized,
			expectedHTTPCode: http.StatusUnauthorized,
			expectedReason:   metav1.StatusReason(ValidationReasonUnauthorized),
		},
		{
			name:             "Forbidden reason",
			reason:           ValidationReasonForbidden,
			expectedHTTPCode: http.StatusForbidden,
			expectedReason:   metav1.StatusReason(ValidationReasonForbidden),
		},
		{
			name:             "Invalid reason",
			reason:           ValidationReasonInvalid,
			expectedHTTPCode: http.StatusBadRequest,
			expectedReason:   metav1.StatusReason(ValidationReasonInvalid),
		},
		{
			name:             "RequestEntityTooLarge reason",
			reason:           ValidationReasonRequestEntityTooLarge,
			expectedHTTPCode: http.StatusRequestEntityTooLarge,
			expectedReason:   metav1.StatusReason(ValidationReasonRequestEntityTooLarge),
		},
		{
			name:             "Default reason (Invalid)",
			reason:           "",
			expectedHTTPCode: http.StatusBadRequest,
			expectedReason:   metav1.StatusReason(ValidationReasonInvalid),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Expression: "false", // Always deny to test reason mapping
				Reason:     testCase.reason,
			}

			err := validation.Provision(caddy.Context{})
			require.NoError(t, err)

			review := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			}

			response, err := validation.Admit(context.Background(), review)

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.False(t, response.Allowed)
			assert.Equal(t, types.UID(uid), response.UID)

			require.NotNil(t, response.Result)
			assert.Equal(t, testCase.expectedHTTPCode, response.Result.Code)

			expectedReason := testCase.expectedReason
			if testCase.reason == "" {
				expectedReason = metav1.StatusReason(ValidationReasonInvalid)
			}
			assert.Equal(t, expectedReason, response.Result.Reason)
		})
	}
}

func TestValidation_MessagePriority(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name              string
		validationName    string
		message           string
		messageExpression string
		expectedMsg       string
		description       string
	}{
		{
			name:        "no message, no name - empty message",
			expectedMsg: "",
			description: "Should have empty message when no message or name is provided",
		},
		{
			name:           "name only - fallback message",
			validationName: "test-validation",
			expectedMsg:    "Rejected by 'test-validation' validation",
			description:    "Should use fallback message when only name is provided",
		},
		{
			name:        "static message only",
			message:     "Static denial message",
			expectedMsg: "Static denial message",
			description: "Should use static message when provided",
		},
		{
			name:           "static message overrides name",
			validationName: "test-validation",
			message:        "Static message wins",
			expectedMsg:    "Static message wins",
			description:    "Static message should override name fallback",
		},
		{
			name:              "message expression only",
			messageExpression: "'Dynamic message'",
			expectedMsg:       "Dynamic message",
			description:       "Should use message expression when provided",
		},
		{
			name:              "message expression overrides static message",
			message:           "Static message",
			messageExpression: "'Dynamic message wins'",
			expectedMsg:       "Dynamic message wins",
			description:       "Message expression should override static message",
		},
		{
			name:              "message expression overrides name and static message",
			validationName:    "test-validation",
			message:           "Static message",
			messageExpression: "'Expression message wins'",
			expectedMsg:       "Expression message wins",
			description:       "Message expression should have highest priority",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			validation := &Validation{
				Name:              testCase.validationName,
				Expression:        "false", // Always deny to test message priority
				Message:           testCase.message,
				MessageExpression: testCase.messageExpression,
			}

			err := validation.Provision(caddy.Context{})
			require.NoError(t, err)

			review := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID:       types.UID(uid),
					Operation: admissionv1.Create,
				},
			}

			response, err := validation.Admit(context.Background(), review)

			require.NoError(t, err, testCase.description)
			require.NotNil(t, response, testCase.description)
			assert.False(t, response.Allowed, testCase.description)
			assert.Equal(t, types.UID(uid), response.UID, testCase.description)

			if testCase.expectedMsg != "" {
				require.NotNil(t, response.Result, testCase.description)
				assert.Equal(t, testCase.expectedMsg, response.Result.Message, testCase.description)
			} else {
				if response.Result != nil {
					assert.Equal(t, "", response.Result.Message, testCase.description)
				}
			}
		})
	}
}

func TestValidation_ContextCancellation(t *testing.T) {
	validation := &Validation{
		Expression: "true",
	}

	err := validation.Provision(caddy.Context{})
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

	response, err := validation.Admit(ctx, review)

	// The CEL evaluation should handle context cancellation
	// In this simple case, it might still succeed because the expression is trivial
	// But we test that it doesn't panic and returns a proper response or error
	if err != nil {
		assert.Contains(t, err.Error(), "context")
	} else {
		assert.NotNil(t, response)
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
			name: "move operation missing from",
			patch: JSONPatch{
				Op:   "move",
				Path: "/metadata/labels/new-label",
			},
			expectError: true,
			errorMsg:    "'from' field is required for move operation",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.patch.Validate()

			if testCase.expectError {
				require.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
			} else {
				assert.NoError(t, err)
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
			name: "multiple invalid patches",
			patches: []JSONPatch{
				{
					Op:    "invalid-op",
					Path:  "/metadata/labels/test",
					Value: "test-value",
				},
				{
					Path:  "/metadata/labels/test2",
					Value: "test-value2",
				},
			},
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			controller := &JSONPatches{
				Patches: testCase.patches,
			}

			err := controller.Validate()

			if testCase.expectError {
				require.Error(t, err)
				if testCase.errorMsg != "" {
					assert.Contains(t, err.Error(), testCase.errorMsg)
				}
			} else {
				assert.NoError(t, err)
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

func TestJSONPatches_UnmarshalCaddyfile(t *testing.T) {
	testCases := []struct {
		name            string
		input           string
		expectedPatches []JSONPatch
		expectError     bool
		errorMsg        string
	}{
		{
			name: "single patch",
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
			},
		},
		{
			name: "patch with array values",
			input: `json_patches {
				patch {
					op add
					path "/spec/ports"
					value 8080 8443 9090
				}
			}`,
			expectedPatches: []JSONPatch{
				{
					Op:    "add",
					Path:  "/spec/ports",
					Value: []any{float64(8080), float64(8443), float64(9090)},
				},
			},
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
				assert.Equal(t, len(testCase.expectedPatches), len(controller.Patches))

				for i, expectedPatch := range testCase.expectedPatches {
					if i < len(controller.Patches) {
						actualPatch := controller.Patches[i]
						assert.Equal(t, expectedPatch.Op, actualPatch.Op)
						assert.Equal(t, expectedPatch.Path, actualPatch.Path)
						assert.Equal(t, expectedPatch.Value, actualPatch.Value)
						assert.Equal(t, expectedPatch.From, actualPatch.From)
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
