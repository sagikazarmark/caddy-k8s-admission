package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// MockHandler is a test implementation of the Handler interface.
// It records whether it was called and can return a predefined response.
type MockHandler struct {
	Response *admissionv1.AdmissionResponse
	Called   bool
}

// Admit implements the Handler interface for testing.
// It marks the handler as called and returns either a predefined response
// or a default allow response.
func (m *MockHandler) Admit(
	_ context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	m.Called = true
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
			handler:     &MockHandler{},
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
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Create mock admission handler
			mockHandler := &MockHandler{
				Response: testCase.mockResponse,
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
