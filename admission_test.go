package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// MockController is a test implementation of the Handler interface.
// It records whether it was called and can return a predefined response or error.
type MockController struct {
	Response *admissionv1.AdmissionResponse
	Error    error
	Called   bool
}

// Admit implements the Handler interface for testing.
// It marks the handler as called and returns either a predefined response,
// a predefined error, or a default allow response.
func (m *MockController) Admit(
	_ context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	m.Called = true
	if m.Error != nil {
		return nil, m.Error
	}
	if m.Response != nil {
		return m.Response, nil
	}

	return &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}, nil
}

func TestWebhook_CaddyModule(t *testing.T) {
	// Test that the Webhook properly implements Caddy module interface
	module := Webhook{}
	moduleInfo := module.CaddyModule()

	assert.Equal(t, caddy.ModuleID("http.handlers.k8s_admission"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(Webhook),
		moduleInfo.New(),
		"Module constructor should return Webhook instance",
	)
}

func TestWebhook_Provision(t *testing.T) {
	testCases := []struct {
		name        string
		handlerRaw  json.RawMessage
		expectError bool
	}{
		{
			name:        "no handler configured",
			handlerRaw:  nil,
			expectError: true,
		},
		{
			name:        "empty handler config",
			handlerRaw:  json.RawMessage(`{}`),
			expectError: true, // Should fail because no handler_type is specified
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := &Webhook{
				ControllerRaw: testCase.handlerRaw,
			}

			// Create a basic Caddy context - we expect provision to fail
			// because we don't have a real module registry in tests
			ctx := caddy.Context{Context: context.Background()}

			err := handler.Provision(ctx)

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWebhook_Validate(t *testing.T) {
	testCases := []struct {
		name        string
		handler     Controller
		expectError bool
	}{
		{
			name:        "no handler",
			handler:     nil,
			expectError: true,
		},
		{
			name:        "valid handler",
			handler:     &MockController{},
			expectError: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			h := Webhook{
				Controller: testCase.handler,
			}

			err := h.Validate()

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWebhook_ServeHTTP(t *testing.T) {
	// Create a valid admission review
	uid := "test-uid"
	admissionReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID: types.UID(uid),
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`),
			},
		},
	}

	testCases := []struct {
		name           string
		method         string
		contentType    string
		body           any
		mockResponse   *admissionv1.AdmissionResponse
		expectedStatus int
		expectedCalled bool
	}{
		{
			name:           "non-POST request",
			method:         "GET",
			contentType:    "application/json",
			body:           admissionReview,
			expectedStatus: 405,
			expectedCalled: false,
		},
		{
			name:           "non-JSON content type",
			method:         "POST",
			contentType:    "text/plain",
			body:           "not json",
			expectedStatus: 400,
			expectedCalled: false,
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			contentType:    "application/json",
			body:           "invalid json",
			expectedStatus: 400,
			expectedCalled: false,
		},
		{
			name:           "missing request",
			method:         "POST",
			contentType:    "application/json",
			body:           admissionv1.AdmissionReview{},
			expectedStatus: 400,
			expectedCalled: false,
		},
		{
			name:           "valid admission review",
			method:         "POST",
			contentType:    "application/json",
			body:           admissionReview,
			expectedStatus: 200,
			expectedCalled: true,
		},
		{
			name:        "custom response from handler",
			method:      "POST",
			contentType: "application/json",
			body:        admissionReview,
			mockResponse: &admissionv1.AdmissionResponse{
				UID:     types.UID(uid),
				Allowed: false,
				Result: &metav1.Status{
					Code:    http.StatusForbidden,
					Message: "Custom deny message",
				},
			},
			expectedStatus: 200,
			expectedCalled: true,
		},
		{
			name:           "controller returns error",
			method:         "POST",
			contentType:    "application/json",
			body:           admissionReview,
			expectedStatus: 500,
			expectedCalled: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create mock admission handler
			mockHandler := &MockController{
				Response: testCase.mockResponse,
			}

			// Set up error for controller error test case
			if testCase.name == "controller returns error" {
				mockHandler.Error = fmt.Errorf("controller failed")
			}

			// Create the main handler
			handler := &Webhook{
				Controller: mockHandler,
				logger:     caddy.Log(), // Initialize logger for tests
			}

			// Create request
			var bodyBytes []byte
			if testCase.body != nil {
				if str, ok := testCase.body.(string); ok {
					bodyBytes = []byte(str)
				} else {
					bodyBytes, _ = json.Marshal(testCase.body)
				}
			}

			req := httptest.NewRequest(testCase.method, "/test", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", testCase.contentType)

			// Create response recorder
			w := httptest.NewRecorder()

			// Call the handler
			err := handler.ServeHTTP(w, req, nil)

			// For error cases, check if we got a caddyhttp.Error
			if testCase.expectedStatus != 200 {
				require.Error(t, err)

				// Check if it's a caddyhttp.HandlerError with the right status
				httpErr, ok := err.(caddyhttp.HandlerError)
				require.True(t, ok, "Expected caddyhttp.HandlerError but got: %T", err)
				assert.Equal(t, testCase.expectedStatus, httpErr.StatusCode)
			} else {
				// For success cases, no error should be returned
				assert.NoError(t, err)
			}

			// Check if mock handler was called
			assert.Equal(t, testCase.expectedCalled, mockHandler.Called)

			// If we expect a successful admission response, verify the response structure
			if testCase.expectedStatus == 200 && testCase.expectedCalled {
				var response admissionv1.AdmissionReview
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err, "Failed to unmarshal response")

				require.NotNil(
					t,
					response.Response,
					"Expected response to contain AdmissionResponse",
				)
				assert.Equal(t, types.UID(uid), response.Response.UID)
			}
		})
	}
}

func TestWebhook_UnmarshalCaddyfile_JSONPatch(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid json_patch configuration",
			input: `k8s_admission json_patch {
				patch {
					op add
					path "/metadata/labels/managed-by"
					value "caddy-admission-webhook"
				}
				patch {
					op replace
					path "/spec/replicas"
					value 3
				}
			}`,
			expectError: false,
		},
		{
			name: "json_patch with complex values",
			input: `k8s_admission json_patch {
				patch {
					op add
					path "/spec/template/spec/containers/0/env/-"
					value {"name":"DATABASE_URL","value":"postgres://..."}
				}
				patch {
					op add
					path "/spec/template/spec/containers/0/ports"
					value 8080 8443 9090
				}
			}`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if wh.ControllerRaw == nil {
				t.Errorf("expected ControllerRaw to be set")
				return
			}

			// Verify the configuration was properly parsed
			var config map[string]any
			if err := json.Unmarshal(wh.ControllerRaw, &config); err != nil {
				t.Errorf("failed to unmarshal controller config: %v", err)
				return
			}

			controllerType, ok := config["controller_type"].(string)
			if !ok {
				t.Errorf("expected controller_type to be string")
				return
			}

			if controllerType != "json_patch" {
				t.Errorf("expected controller_type to be 'json_patch', got %q", controllerType)
			}

			// Debug: print the actual JSON structure
			t.Logf("Actual config JSON: %+v", config)

			// For json_patch controller, verify patches were parsed
			if controllerType == "json_patch" {
				patches, ok := config["patches"]
				if !ok {
					t.Errorf("expected patches field for json_patch controller")
					return
				}

				patchesSlice, ok := patches.([]any)
				if !ok {
					t.Errorf("expected patches to be slice")
					return
				}

				if len(patchesSlice) == 0 {
					t.Errorf("expected at least one patch")
				}
			}
		})
	}
}

func TestWebhook_UnmarshalCaddyfile_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "no controller type specified",
			input: `k8s_admission {
			}`,
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name:        "invalid controller type",
			input:       `k8s_admission invalid_type`,
			expectError: true,
			errorMsg:    "module not registered",
		},
		{
			name: "json_patch with unknown directive",
			input: `k8s_admission json_patch {
				patch {
					op add
					path "/test"
					value "test"
					unknown_directive
				}
			}`,
			expectError: true,
			errorMsg:    "unknown patch directive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
		})
	}
}

func TestWebhook_UnmarshalCaddyfile_AlwaysAllow(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid always_allow configuration",
			input:       `k8s_admission always_allow`,
			expectError: false,
		},
		{
			name:        "always_allow with extra tokens",
			input:       `k8s_admission always_allow extra`,
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name: "always_allow with unexpected block",
			input: `k8s_admission always_allow {
				something here
			}`,
			expectError: true,
			errorMsg:    "unexpected block for 'always_allow' controller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if wh.ControllerRaw == nil {
				t.Errorf("expected ControllerRaw to be set")
				return
			}

			// Verify the configuration was properly parsed
			var config map[string]any
			if err := json.Unmarshal(wh.ControllerRaw, &config); err != nil {
				t.Errorf("failed to unmarshal controller config: %v", err)
				return
			}

			controllerType, ok := config["controller_type"].(string)
			if !ok {
				t.Errorf("expected controller_type to be string")
				return
			}

			if controllerType != "always_allow" {
				t.Errorf("expected controller_type to be 'always_allow', got %q", controllerType)
			}
		})
	}
}

func TestWebhook_UnmarshalCaddyfile_AlwaysDeny(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid always_deny configuration",
			input:       `k8s_admission always_deny`,
			expectError: false,
		},
		{
			name:        "always_deny with extra tokens",
			input:       `k8s_admission always_deny extra`,
			expectError: true,
			errorMsg:    "wrong argument count",
		},
		{
			name: "always_deny with unexpected block",
			input: `k8s_admission always_deny {
				something here
			}`,
			expectError: true,
			errorMsg:    "unexpected block for 'always_deny' controller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if wh.ControllerRaw == nil {
				t.Errorf("expected ControllerRaw to be set")
				return
			}

			// Verify the configuration was properly parsed
			var config map[string]any
			if err := json.Unmarshal(wh.ControllerRaw, &config); err != nil {
				t.Errorf("failed to unmarshal controller config: %v", err)
				return
			}

			controllerType, ok := config["controller_type"].(string)
			if !ok {
				t.Errorf("expected controller_type to be string")
				return
			}

			if controllerType != "always_deny" {
				t.Errorf("expected controller_type to be 'always_deny', got %q", controllerType)
			}
		})
	}
}

func TestWebhook_UnmarshalCaddyfile_ValidationPolicy(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid validation_policy with allow action",
			input: `k8s_admission validation_policy {
				expression "name == 'allowed-pod'"
				action allow
			}`,
			expectError: false,
		},
		{
			name: "valid validation_policy with deny action",
			input: `k8s_admission validation_policy {
				expression "requestNamespace == 'kube-system'"
				action deny
			}`,
			expectError: false,
		},
		{
			name: "validation_policy with complex expression",
			input: `k8s_admission validation_policy {
				expression "has(object.metadata.labels) && object.metadata.labels['app'] == 'critical'"
				action deny
			}`,
			expectError: false,
		},
		{
			name: "validation_policy with missing expression",
			input: `k8s_admission validation_policy {
				action allow
			}`,
			expectError: false, // Will be caught during Provision
		},
		{
			name: "validation_policy with missing action",
			input: `k8s_admission validation_policy {
				expression "true"
			}`,
			expectError: false, // Will be caught during validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if wh.ControllerRaw == nil {
				t.Errorf("expected ControllerRaw to be set")
				return
			}

			// Verify the configuration was properly parsed
			var config map[string]any
			if err := json.Unmarshal(wh.ControllerRaw, &config); err != nil {
				t.Errorf("failed to unmarshal controller config: %v", err)
				return
			}

			controllerType, ok := config["controller_type"].(string)
			if !ok {
				t.Errorf("expected controller_type to be string")
				return
			}

			if controllerType != "validation_policy" {
				t.Errorf(
					"expected controller_type to be 'validation_policy', got %q",
					controllerType,
				)
			}
		})
	}
}

func TestWebhook_Integration_EndToEnd(t *testing.T) {
	// Test various controller configurations in a more realistic scenario
	tests := []struct {
		name       string
		config     string
		shouldWork bool
		validate   func(t *testing.T, wh *Webhook)
	}{
		{
			name:       "always_allow controller",
			config:     `k8s_admission always_allow`,
			shouldWork: true,
			validate: func(t *testing.T, wh *Webhook) {
				var config map[string]any
				require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))
				assert.Equal(t, "always_allow", config["controller_type"])
			},
		},
		{
			name:       "always_deny controller",
			config:     `k8s_admission always_deny`,
			shouldWork: true,
			validate: func(t *testing.T, wh *Webhook) {
				var config map[string]any
				require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))
				assert.Equal(t, "always_deny", config["controller_type"])
			},
		},
		{
			name: "json_patch with simple patch",
			config: `k8s_admission json_patch {
				patch {
					op add
					path "/metadata/labels/managed-by"
					value "caddy"
				}
			}`,
			shouldWork: true,
			validate: func(t *testing.T, wh *Webhook) {
				var config map[string]any
				require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))
				assert.Equal(t, "json_patch", config["controller_type"])
				patches := config["patches"].([]any)
				require.Len(t, patches, 1)
				patch := patches[0].(map[string]any)
				assert.Equal(t, "add", patch["op"])
				assert.Equal(t, "/metadata/labels/managed-by", patch["path"])
				assert.Equal(t, "caddy", patch["value"])
			},
		},
		{
			name: "validation_policy with complex logic",
			config: `k8s_admission validation_policy {
				expression "operation == 'CREATE' && has(object.metadata.namespace) && object.metadata.namespace != 'kube-system'"
				action allow
			}`,
			shouldWork: true,
			validate: func(t *testing.T, wh *Webhook) {
				var config map[string]any
				require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))
				assert.Equal(t, "validation_policy", config["controller_type"])
				assert.Contains(t, config["expression"], "operation == 'CREATE'")
				assert.Equal(t, "allow", config["action"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the configuration
			d := caddyfile.NewTestDispenser(tt.config)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)
			if !tt.shouldWork {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err, "Configuration parsing should succeed")
			require.NotNil(t, wh.ControllerRaw, "ControllerRaw should be set")

			// Run validation if provided
			if tt.validate != nil {
				tt.validate(t, wh)
			}
		})
	}
}

func TestWebhook_UnmarshalCaddyfile_ComplexScenarios(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		validate    func(t *testing.T, wh *Webhook)
	}{
		{
			name: "json_patch with array values",
			input: `k8s_admission json_patch {
				patch {
					op add
					path "/spec/ports"
					value [8080, 8443, 9090]
				}
			}`,
			expectError: false,
			validate: func(t *testing.T, wh *Webhook) {
				var config map[string]any
				require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))
				patches := config["patches"].([]any)
				require.Len(t, patches, 1)
				patch := patches[0].(map[string]any)
				assert.Equal(t, "add", patch["op"])
				assert.Equal(t, "/spec/ports", patch["path"])
				// The value should be parsed as an array
				value := patch["value"].([]any)
				assert.Len(t, value, 3)
			},
		},
		{
			name: "json_patch with object values",
			input: `k8s_admission json_patch {
				patch {
					op add
					path "/metadata/annotations/config"
					value {"key":"value","number":42}
				}
			}`,
			expectError: false,
			validate: func(t *testing.T, wh *Webhook) {
				var config map[string]any
				require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))
				patches := config["patches"].([]any)
				patch := patches[0].(map[string]any)
				value := patch["value"].(map[string]any)
				assert.Equal(t, "value", value["key"])
				assert.Equal(t, float64(42), value["number"]) // JSON numbers become float64
			},
		},
		{
			name: "validation_policy with multiline expression",
			input: `k8s_admission validation_policy {
				expression "operation == 'CREATE' && has(object.spec.containers) && size(object.spec.containers) > 0"
				action deny
			}`,
			expectError: false,
			validate: func(t *testing.T, wh *Webhook) {
				var config map[string]any
				require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))
				assert.Equal(t, "validation_policy", config["controller_type"])
				assert.Contains(t, config["expression"], "operation == 'CREATE'")
				assert.Equal(t, "deny", config["action"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, wh.ControllerRaw)

			if tt.validate != nil {
				tt.validate(t, wh)
			}
		})
	}
}

func TestWebhook_ControllerInterfaceDetection(t *testing.T) {
	// Test that the webhook correctly detects which controllers implement caddyfile.Unmarshaler
	tests := []struct {
		name           string
		input          string
		expectError    bool
		hasUnmarshaler bool
	}{
		{
			name:           "always_allow - no unmarshaler",
			input:          `k8s_admission always_allow`,
			expectError:    false,
			hasUnmarshaler: false,
		},
		{
			name:           "always_deny - no unmarshaler",
			input:          `k8s_admission always_deny`,
			expectError:    false,
			hasUnmarshaler: false,
		},
		{
			name: "json_patch - has unmarshaler",
			input: `k8s_admission json_patch {
				patch {
					op add
					path "/test"
					value "test"
				}
			}`,
			expectError:    false,
			hasUnmarshaler: true,
		},
		{
			name: "validation_policy - has unmarshaler",
			input: `k8s_admission validation_policy {
				expression "true"
				action allow
			}`,
			expectError:    false,
			hasUnmarshaler: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, wh.ControllerRaw)

			// Verify the configuration was created correctly
			var config map[string]any
			require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))

			controllerType, ok := config["controller_type"].(string)
			require.True(t, ok, "controller_type should be present")

			// Load the module to check if it implements caddyfile.Unmarshaler
			modID := "k8s.admission." + controllerType
			modVal, err := caddy.GetModule(modID)
			require.NoError(t, err)

			controller := modVal.New()
			_, hasUnmarshaler := controller.(caddyfile.Unmarshaler)

			assert.Equal(t, tt.hasUnmarshaler, hasUnmarshaler,
				"Expected hasUnmarshaler=%v for %s controller", tt.hasUnmarshaler, controllerType)
		})
	}
}

func TestWebhook_ConfigurationBehaviorDocumentation(t *testing.T) {
	// This test documents the expected configuration behavior for each controller type
	tests := []struct {
		name                   string
		input                  string
		expectedControllerType string
		expectError            bool
		description            string
	}{
		{
			name:                   "always_allow_simple",
			input:                  `k8s_admission always_allow`,
			expectedControllerType: "always_allow",
			expectError:            false,
			description:            "Simple controllers like always_allow require no configuration block",
		},
		{
			name:                   "always_deny_simple",
			input:                  `k8s_admission always_deny`,
			expectedControllerType: "always_deny",
			expectError:            false,
			description:            "Simple controllers like always_deny require no configuration block",
		},
		{
			name:        "always_allow_with_args_fails",
			input:       `k8s_admission always_allow extra_arg`,
			expectError: true,
			description: "Simple controllers reject extra arguments",
		},
		{
			name: "always_allow_with_block_fails",
			input: `k8s_admission always_allow {
				something
			}`,
			expectError: true,
			description: "Simple controllers reject configuration blocks",
		},
		{
			name: "json_patch_requires_block",
			input: `k8s_admission json_patch {
				patch {
					op add
					path "/metadata/labels/test"
					value "configured"
				}
			}`,
			expectedControllerType: "json_patch",
			expectError:            false,
			description:            "Complex controllers like json_patch require configuration blocks",
		},
		{
			name: "validation_policy_requires_block",
			input: `k8s_admission validation_policy {
				expression "true"
				action allow
			}`,
			expectedControllerType: "validation_policy",
			expectError:            false,
			description:            "Complex controllers like validation_policy require configuration blocks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)

			d := caddyfile.NewTestDispenser(tt.input)
			wh := &Webhook{}

			err := wh.UnmarshalCaddyfile(d)

			if tt.expectError {
				assert.Error(t, err, "Expected error for: %s", tt.description)
				return
			}

			require.NoError(t, err, "Unexpected error for: %s", tt.description)
			require.NotNil(t, wh.ControllerRaw, "ControllerRaw should be set")

			// Verify the controller type
			var config map[string]any
			require.NoError(t, json.Unmarshal(wh.ControllerRaw, &config))

			controllerType, ok := config["controller_type"].(string)
			require.True(t, ok, "controller_type should be present")
			assert.Equal(t, tt.expectedControllerType, controllerType)
		})
	}
}
