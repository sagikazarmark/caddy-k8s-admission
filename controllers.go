package admission

import (
	"context"
	"encoding/json"
	"maps"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	caddy.RegisterModule(AlwaysAllow{})
	caddy.RegisterModule(AlwaysDeny{})
	caddy.RegisterModule(AnnotationInjector{})
}

// AlwaysAllow is a simple admission webhook [Controller] that always allows requests.
//
// This is useful for testing or as a default fallback handler.
type AlwaysAllow struct{}

// CaddyModule returns the Caddy module information.
func (AlwaysAllow) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.always_allow",
		New: func() caddy.Module { return new(AlwaysAllow) },
	}
}

// Admit processes an admission review and always returns an allow response.
//
// Implements the [Controller] interface.
func (a AlwaysAllow) Admit(
	_ context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	return &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}, nil
}

// Interface guard
var _ Controller = (*AlwaysAllow)(nil)

// AlwaysDeny is a simple admission webhook [Controller] that always rejects requests.
//
// This is useful for testing or as a default fallback handler.
type AlwaysDeny struct{}

// CaddyModule returns the Caddy module information.
func (AlwaysDeny) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.always_deny",
		New: func() caddy.Module { return new(AlwaysDeny) },
	}
}

// Admit processes an admission review and always returns a deny response.
//
// Implements the [Controller] interface.
func (a AlwaysDeny) Admit(
	_ context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	return &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: false,
	}, nil
}

// Interface guard
var _ Controller = (*AlwaysDeny)(nil)

// AnnotationInjector is an admission webhook [Controller] that injects annotations into Kubernetes resources.
//
// It uses JSON Patch operations to add the specified annotations to the resource's metadata.
type AnnotationInjector struct {
	// Annotations is a map of annotation keys to values that will be injected into resources.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AnnotationInjector) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.annotation_injector",
		New: func() caddy.Module { return new(AnnotationInjector) },
	}
}

// Provision sets up the annotation injector.
func (a *AnnotationInjector) Provision(_ caddy.Context) error {
	if a.Annotations == nil {
		a.Annotations = make(map[string]string)
	}

	return nil
}

// Validate validates the configuration.
func (a AnnotationInjector) Validate() error {
	// if len(a.Annotations) == 0 {
	// 	return fmt.Errorf("at least one annotation must be configured")
	// }
	return nil
}

// Admit processes an admission review and injects annotations using JSON Patch.
//
// Implements the [Controller] interface.
func (a AnnotationInjector) Admit(
	_ context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	// If no annotations configured, allow without modification
	if len(a.Annotations) == 0 {
		return &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: true,
		}, nil
	}

	var obj unstructured.Unstructured

	if err := json.Unmarshal(review.Request.Object.Raw, &obj); err != nil {
		return nil, err
	}

	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	maps.Copy(annotations, a.Annotations)

	patch, _ := json.Marshal([]map[string]any{
		{"op": "add", "path": "/metadata/annotations", "value": annotations},
	})

	patchType := admissionv1.PatchTypeJSONPatch

	return &admissionv1.AdmissionResponse{
		UID:       review.Request.UID,
		Allowed:   true,
		Patch:     patch,
		PatchType: &patchType,
	}, nil
}

// escapeJSONPointer escapes a string for use in a JSON Pointer path.
// According to RFC 6901, '~' becomes '~0' and '/' becomes '~1'.
func escapeJSONPointer(s string) string {
	result := ""
	for _, r := range s {
		switch r {
		case '~':
			result += "~0"
		case '/':
			result += "~1"
		default:
			result += string(r)
		}
	}
	return result
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (a *AnnotationInjector) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if a.Annotations == nil {
		a.Annotations = make(map[string]string)
	}

	// Parse annotation key-value pairs from Caddyfile
	for d.NextBlock(0) {
		key := d.Val()
		if !d.NextArg() {
			return d.ArgErr()
		}
		value := d.Val()
		a.Annotations[key] = value
	}

	return nil
}

// Interface guards
var (
	_ Controller            = (*AnnotationInjector)(nil)
	_ caddy.Provisioner     = (*AnnotationInjector)(nil)
	_ caddy.Validator       = (*AnnotationInjector)(nil)
	_ caddyfile.Unmarshaler = (*AnnotationInjector)(nil)
)
