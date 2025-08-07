package admission_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

//go:embed Caddyfile
var embeddedCaddyfile string

const testPort = "9090"

func TestCaddyfileIntegration(t *testing.T) {
	// Replace localhost with the test port and add global options
	testCaddyfile := fmt.Sprintf(`{
	skip_install_trust
	admin localhost:2999
	http_port %s
	https_port 9443
	auto_https off
}

%s`, testPort, strings.Replace(embeddedCaddyfile, "localhost", "localhost:"+testPort, 1))

	tester := caddytest.NewTester(t)
	tester.InitServer(testCaddyfile, "caddyfile")

	// Give the server a moment to start up
	time.Sleep(200 * time.Millisecond)

	t.Run("always_allow", func(t *testing.T) {
		review := createTestAdmissionReview(t, "CREATE", nil)
		resp := sendAdmissionRequest(t, tester, "/allow", review)

		assert.True(t, resp.Response.Allowed, "Expected request to be allowed")
		assert.Equal(t, review.Request.UID, resp.Response.UID, "UID mismatch")
		assert.Nil(t, resp.Response.Patch, "Expected no patches for allow route")
	})

	t.Run("always_deny", func(t *testing.T) {
		review := createTestAdmissionReview(t, "CREATE", nil)
		resp := sendAdmissionRequest(t, tester, "/deny", review)

		assert.False(t, resp.Response.Allowed, "Expected request to be denied")
		assert.Equal(t, review.Request.UID, resp.Response.UID, "UID mismatch")
		// Note: Result may be nil for simple denial responses, which is acceptable
		if resp.Response.Result != nil {
			assert.NotEmpty(
				t,
				resp.Response.Result.Message,
				"Expected denial message when result is present",
			)
		}
	})

	t.Run("validation", func(t *testing.T) {
		// Test CREATE operation with custom message - should be denied by validation with custom message
		createReview := createTestAdmissionReview(t, "CREATE", map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "test-pod",
				"namespace": "default",
			},
		})
		createResp := sendAdmissionRequest(t, tester, "/deny/create", createReview)

		assert.False(
			t,
			createResp.Response.Allowed,
			"CREATE operations should be denied by validation",
		)
		assert.Equal(t, createReview.Request.UID, createResp.Response.UID, "UID mismatch")

		// Check that custom message is present
		require.NotNil(t, createResp.Response.Result, "Expected result with custom message")
		assert.Contains(
			t,
			createResp.Response.Result.Message,
			"CREATE operations are not allowed for Pod resources",
			"Expected custom denial message",
		)

		// Test UPDATE operation - should be allowed by validation (no message should be present)
		updateReview := createTestAdmissionReview(t, "UPDATE", map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "test-pod",
				"namespace": "default",
			},
		})
		updateResp := sendAdmissionRequest(t, tester, "/deny/create", updateReview)

		assert.True(
			t,
			updateResp.Response.Allowed,
			"UPDATE operations should be allowed by validation",
		)
		assert.Equal(t, updateReview.Request.UID, updateResp.Response.UID, "UID mismatch")
		assert.Nil(t, updateResp.Response.Result, "Expected no result for allowed operations")
	})

	t.Run("json_patch", func(t *testing.T) {
		review := createTestAdmissionReview(t, "CREATE", map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "test-pod",
				"namespace": "default",
				"labels": map[string]any{
					"existing-label": "existing-value",
					"app":            "test-app",
				},
			},
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name":  "test-container",
						"image": "nginx:latest",
					},
				},
			},
		})
		resp := sendAdmissionRequest(t, tester, "/patch", review)

		assert.True(t, resp.Response.Allowed, "Expected request to be allowed")
		assert.Equal(t, review.Request.UID, resp.Response.UID, "UID mismatch")

		// Check that patch was applied
		require.NotNil(t, resp.Response.Patch, "Expected patch to be applied")
		require.NotNil(t, resp.Response.PatchType, "Expected patch type to be set")
		assert.Equal(
			t,
			admissionv1.PatchTypeJSONPatch,
			*resp.Response.PatchType,
			"Expected JSONPatch type",
		)

		// Verify the patch content contains the expected mutation
		patchStr := string(resp.Response.Patch)
		assert.Contains(t, patchStr, "single-patch", "Expected patch to contain single-patch label")
		assert.Contains(
			t,
			patchStr,
			"applied",
			"Expected patch to contain applied value",
		)

		// Parse and validate the patch structure
		var patches []map[string]any
		err := json.Unmarshal(resp.Response.Patch, &patches)
		require.NoError(t, err, "Failed to parse patch JSON")
		require.Len(t, patches, 1, "Expected exactly one patch operation")

		patch := patches[0]
		assert.Equal(t, "add", patch["op"], "Expected add operation")
		assert.Equal(
			t,
			"/metadata/labels/single-patch",
			patch["path"],
			"Expected correct patch path",
		)
		assert.Equal(t, "applied", patch["value"], "Expected correct patch value")
	})

	t.Run("json_patches", func(t *testing.T) {
		review := createTestAdmissionReview(t, "CREATE", map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "test-pod",
				"namespace": "default",
				"labels": map[string]any{
					"existing-label": "existing-value",
					"app":            "test-app",
				},
			},
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name":  "test-container",
						"image": "nginx:latest",
					},
				},
			},
		})
		resp := sendAdmissionRequest(t, tester, "/patches", review)

		assert.True(t, resp.Response.Allowed, "Expected request to be allowed")
		assert.Equal(t, review.Request.UID, resp.Response.UID, "UID mismatch")

		// Check that patches were applied
		require.NotNil(t, resp.Response.Patch, "Expected patches to be applied")
		require.NotNil(t, resp.Response.PatchType, "Expected patch type to be set")
		assert.Equal(
			t,
			admissionv1.PatchTypeJSONPatch,
			*resp.Response.PatchType,
			"Expected JSONPatch type",
		)

		// Verify the patch content contains the expected mutations
		patchStr := string(resp.Response.Patch)
		assert.Contains(t, patchStr, "mutated-by", "Expected patch to contain mutated-by label")
		assert.Contains(
			t,
			patchStr,
			"caddy-admission-webhook",
			"Expected patch to contain webhook identifier",
		)
		assert.Contains(
			t,
			patchStr,
			"caddy-admission-controller",
			"Expected patch to contain controller label",
		)
		assert.Contains(
			t,
			patchStr,
			"json_patches",
			"Expected patch to contain json_patches value",
		)

		// Parse and validate the patch structure
		var patches []map[string]any
		err := json.Unmarshal(resp.Response.Patch, &patches)
		require.NoError(t, err, "Failed to parse patch JSON")
		require.Len(t, patches, 2, "Expected exactly two patch operations")

		// Verify first patch
		patch1 := patches[0]
		assert.Equal(t, "add", patch1["op"], "Expected add operation for first patch")
		assert.Equal(
			t,
			"/metadata/labels/mutated-by",
			patch1["path"],
			"Expected correct path for first patch",
		)
		assert.Equal(
			t,
			"caddy-admission-webhook",
			patch1["value"],
			"Expected correct value for first patch",
		)

		// Verify second patch
		patch2 := patches[1]
		assert.Equal(t, "add", patch2["op"], "Expected add operation for second patch")
		assert.Equal(
			t,
			"/metadata/labels/caddy-admission-controller",
			patch2["path"],
			"Expected correct path for second patch",
		)
		assert.Equal(t, "json_patches", patch2["value"], "Expected correct value for second patch")
	})
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

// Helper function to send an admission request and parse the response
func sendAdmissionRequest(
	t *testing.T,
	tester *caddytest.Tester,
	path string,
	review *admissionv1.AdmissionReview,
) *admissionv1.AdmissionReview {
	reviewJSON, err := json.Marshal(review)
	require.NoError(t, err, "Failed to marshal admission review")

	url := fmt.Sprintf("http://localhost:%s%s", testPort, path)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reviewJSON))
	require.NoError(t, err, "Failed to create request")
	req.Header.Set("Content-Type", "application/json")

	resp := tester.AssertResponseCode(req, http.StatusOK)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	var responseReview admissionv1.AdmissionReview
	err = json.Unmarshal(body, &responseReview)
	require.NoError(t, err, "Failed to unmarshal response")

	require.NotNil(t, responseReview.Response, "Expected response, got nil")
	return &responseReview
}
