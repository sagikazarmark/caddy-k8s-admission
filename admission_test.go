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
