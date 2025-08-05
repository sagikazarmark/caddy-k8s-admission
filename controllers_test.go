package admission

import (
	"context"
	"encoding/json"
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
		moduleID string
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
			name:     "AnnotationInjector",
			moduleID: "k8s.admission.annotation_injector",
			module:   &AnnotationInjector{},
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

// TestAnnotationInjector_CaddyModule tests the CaddyModule method
func TestAnnotationInjector_CaddyModule(t *testing.T) {
	module := AnnotationInjector{}
	moduleInfo := module.CaddyModule()

	assert.Equal(t, caddy.ModuleID("k8s.admission.annotation_injector"), moduleInfo.ID)
	require.NotNil(t, moduleInfo.New, "Module constructor should not be nil")
	assert.IsType(
		t,
		new(AnnotationInjector),
		moduleInfo.New(),
		"Module constructor should return AnnotationInjector instance",
	)
}

// TestAnnotationInjector_Provision tests the Provision method
func TestAnnotationInjector_Provision(t *testing.T) {
	injector := &AnnotationInjector{}
	ctx := caddy.Context{Context: context.Background()}

	err := injector.Provision(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, injector.Annotations)
}

// TestAnnotationInjector_Validate tests the Validate method
func TestAnnotationInjector_Validate(t *testing.T) {
	testCases := []struct {
		name        string
		annotations map[string]string
		expectError bool
	}{
		{
			name: "valid annotations",
			annotations: map[string]string{
				"example.com/annotation": "value",
			},
			expectError: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			injector := AnnotationInjector{
				Annotations: testCase.annotations,
			}

			err := injector.Validate()

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAnnotationInjector_Admit tests the Admit method
func TestAnnotationInjector_Admit(t *testing.T) {
	uid := "test-uid"

	testCases := []struct {
		name        string
		annotations map[string]string
		objectJSON  string
		expectAllow bool
		expectPatch bool
		expectedMsg string
	}{
		{
			name:        "no annotations configured",
			annotations: map[string]string{},
			objectJSON:  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`,
			expectAllow: true,
			expectPatch: false,
		},
		{
			name: "add annotation to existing metadata",
			annotations: map[string]string{
				"example.com/injected": "true",
			},
			objectJSON:  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`,
			expectAllow: true,
			expectPatch: true,
		},
		{
			name: "add annotation with existing annotations",
			annotations: map[string]string{
				"example.com/injected": "true",
			},
			objectJSON:  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test","annotations":{"existing":"value"}}}`,
			expectAllow: true,
			expectPatch: true,
		},
		{
			name: "add annotation to object without metadata",
			annotations: map[string]string{
				"example.com/injected": "true",
			},
			objectJSON:  `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[]}}`,
			expectAllow: true,
			expectPatch: true,
		},
		{
			name: "handle special characters in annotation key",
			annotations: map[string]string{
				"example.com/key~with/special": "value",
			},
			objectJSON:  `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test"}}`,
			expectAllow: true,
			expectPatch: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			injector := AnnotationInjector{
				Annotations: testCase.annotations,
			}

			admissionReview := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: types.UID(uid),
					Object: runtime.RawExtension{
						Raw: []byte(testCase.objectJSON),
					},
				},
			}

			response, err := injector.Admit(context.Background(), admissionReview)

			require.NoError(t, err)
			require.NotNil(t, response)
			assert.Equal(t, types.UID(uid), response.UID)
			assert.Equal(t, testCase.expectAllow, response.Allowed)

			if testCase.expectPatch {
				assert.NotNil(t, response.Patch)
				assert.NotNil(t, response.PatchType)
				assert.Equal(t, admissionv1.PatchTypeJSONPatch, *response.PatchType)

				// Verify patch is valid JSON
				var patches []map[string]interface{}
				err := json.Unmarshal(response.Patch, &patches)
				assert.NoError(t, err)
				assert.NotEmpty(t, patches)
			} else {
				assert.Nil(t, response.Patch)
				assert.Nil(t, response.PatchType)
			}

			if testCase.expectedMsg != "" {
				require.NotNil(t, response.Result)
				assert.Contains(t, response.Result.Message, testCase.expectedMsg)
			}
		})
	}
}

// TestEscapeJSONPointer tests the escapeJSONPointer function
func TestEscapeJSONPointer(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "simple",
			expected: "simple",
		},
		{
			input:    "with/slash",
			expected: "with~1slash",
		},
		{
			input:    "with~tilde",
			expected: "with~0tilde",
		},
		{
			input:    "with~/both",
			expected: "with~0~1both",
		},
		{
			input:    "example.com/annotation~key",
			expected: "example.com~1annotation~0key",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.input, func(t *testing.T) {
			result := escapeJSONPointer(testCase.input)
			assert.Equal(t, testCase.expected, result)
		})
	}
}

// TestAnnotationInjector_Provision_Enhanced tests additional provision scenarios
func TestAnnotationInjector_Provision_Enhanced(t *testing.T) {
	testCases := []struct {
		name     string
		injector *AnnotationInjector
	}{
		{
			name:     "completely new injector",
			injector: &AnnotationInjector{},
		},
		{
			name: "injector with pre-existing annotations",
			injector: &AnnotationInjector{
				Annotations: map[string]string{
					"existing": "value",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := caddy.Context{Context: context.Background()}
			err := testCase.injector.Provision(ctx)

			assert.NoError(t, err)
			assert.NotNil(t, testCase.injector.Annotations)
		})
	}
}

// TestAnnotationInjector_UnmarshalCaddyfile_Enhanced tests additional Caddyfile parsing scenarios
func TestAnnotationInjector_UnmarshalCaddyfile_Enhanced(t *testing.T) {
	testCases := []struct {
		name                string
		input               string
		expectedAnnotations map[string]string
		expectError         bool
	}{
		{
			name: "single annotation",
			input: `annotation_injector {
				example.com/injected true
			}`,
			expectedAnnotations: map[string]string{
				"example.com/injected": "true",
			},
			expectError: false,
		},
		{
			name: "multiple annotations",
			input: `annotation_injector {
				example.com/injected true
				test.io/env production
				version 1.0.0
			}`,
			expectedAnnotations: map[string]string{
				"example.com/injected": "true",
				"test.io/env":          "production",
				"version":              "1.0.0",
			},
			expectError: false,
		},
		{
			name: "no annotations",
			input: `annotation_injector {
			}`,
			expectedAnnotations: map[string]string{},
			expectError:         false,
		},
		{
			name: "annotation with quoted value",
			input: `annotation_injector {
				description "This is a test annotation"
			}`,
			expectedAnnotations: map[string]string{
				"description": "This is a test annotation",
			},
			expectError: false,
		},
		{
			name: "annotations with special characters",
			input: `annotation_injector {
				"example.com/key~with/special" "special-value"
				"test/key-with-dashes" "dash-value"
			}`,
			expectedAnnotations: map[string]string{
				"example.com/key~with/special": "special-value",
				"test/key-with-dashes":         "dash-value",
			},
			expectError: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(testCase.input)
			dispenser.Next() // consume directive name

			injector := &AnnotationInjector{}
			err := injector.UnmarshalCaddyfile(dispenser)

			if testCase.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.expectedAnnotations, injector.Annotations)
			}
		})
	}
}

func TestAnnotationInjector_ContextCancellation(t *testing.T) {
	injector := AnnotationInjector{
		Annotations: map[string]string{
			"test": "value",
		},
	}

	uid := types.UID("cancel-test")
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	response, err := injector.Admit(ctx, review)

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, uid, response.UID)
	assert.True(t, response.Allowed)
	assert.NotNil(t, response.Patch)
}

// TestAnnotationInjector_LargeObject tests behavior with large Kubernetes objects
func TestAnnotationInjector_LargeObject(t *testing.T) {
	injector := AnnotationInjector{
		Annotations: map[string]string{
			"test": "value",
		},
	}

	// Create a large object with many fields
	largeObject := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "test-pod",
			"namespace": "default",
			"labels": map[string]any{
				"app":     "test",
				"version": "1.0.0",
			},
		},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  "container1",
					"image": "nginx:latest",
					"env": []any{
						map[string]any{
							"name":  "ENV1",
							"value": "value1",
						},
						map[string]any{
							"name":  "ENV2",
							"value": "value2",
						},
					},
				},
			},
		},
	}

	objectJSON, err := json.Marshal(largeObject)
	require.NoError(t, err)

	uid := types.UID("large-object-test")
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: uid,
			Kind: metav1.GroupVersionKind{
				Version: "v1",
				Kind:    "Pod",
			},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: objectJSON,
			},
		},
	}

	response, err := injector.Admit(context.Background(), review)

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, uid, response.UID)
	assert.True(t, response.Allowed)
	assert.NotNil(t, response.Patch)

	// Verify the patch contains our annotation
	var patches []map[string]any
	err = json.Unmarshal(response.Patch, &patches)
	require.NoError(t, err)
	require.Len(t, patches, 1)

	patch := patches[0]
	annotations, ok := patch["value"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "value", annotations["test"])
}
