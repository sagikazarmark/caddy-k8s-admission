package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/cel-go/cel"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	caddy.RegisterModule(AlwaysAllow{})
	caddy.RegisterModule(AlwaysDeny{})
	caddy.RegisterModule(AnnotationInjector{})
	caddy.RegisterModule(ValidationPolicy{})
}

// AlwaysAllow is a simple admission webhook controller that always allows requests.
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

// AlwaysDeny is a simple admission webhook controller that always rejects requests.
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

// AnnotationInjector is an admission webhook controller that injects annotations into Kubernetes resources.
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

// UnmarshalCaddyfile implements [caddyfile.Unmarshaler].
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

// Interface guards
var (
	_ Controller            = (*AnnotationInjector)(nil)
	_ caddy.Provisioner     = (*AnnotationInjector)(nil)
	_ caddy.Validator       = (*AnnotationInjector)(nil)
	_ caddyfile.Unmarshaler = (*AnnotationInjector)(nil)
)

// PolicyAction represents the action to take when a validation policy is matched.
type PolicyAction string

const (
	// PolicyActionAllow allows the request when the policy matches.
	PolicyActionAllow PolicyAction = "allow"

	// PolicyActionDeny denies the request when the policy matches.
	PolicyActionDeny PolicyAction = "deny"
)

// ValidationPolicy is an admission webhook controller that validates resources using CEL expressions.
//
// It evaluates the provided expression against the resource and takes the specified action.
type ValidationPolicy struct {
	// Expression is the validation expression to evaluate against the resource.
	Expression string `json:"expression,omitempty"`

	// Action is the action to take when the expression matches (allow or deny).
	Action PolicyAction `json:"action,omitempty"`

	program cel.Program
}

// CaddyModule returns the Caddy module information.
func (ValidationPolicy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.validation_policy",
		New: func() caddy.Module { return new(ValidationPolicy) },
	}
}

// Provision sets up the validation policy.
func (vp *ValidationPolicy) Provision(_ caddy.Context) error {
	env, err := cel.NewEnv(
		cel.Variable("name", cel.StringType),                                // optional
		cel.Variable("requestNamespace", cel.StringType),                    // optional
		cel.Variable("operation", cel.StringType),                           // required
		cel.Variable("object", cel.MapType(cel.StringType, cel.AnyType)),    // optional
		cel.Variable("oldObject", cel.MapType(cel.StringType, cel.AnyType)), // optional
	)
	if err != nil {
		return fmt.Errorf("initializing CEL environment: %w", err)
	}

	ast, iss := env.Compile(vp.Expression)
	if iss.Err() != nil {
		return fmt.Errorf("compile CEL expression: %w", iss.Err())
	}

	if !ast.OutputType().IsEquivalentType(cel.BoolType) {
		return fmt.Errorf("expression must return bool, got %v", ast.OutputType())
	}

	program, err := env.Program(ast)
	if err != nil {
		return fmt.Errorf("generating CEL program: %w", err)
	}

	vp.program = program

	return nil
}

// UnmarshalCaddyfile implements [caddyfile.Unmarshaler].
func (vp *ValidationPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.NextBlock(0) {
		switch d.Val() {
		case "expression":
			if !d.NextArg() {
				return d.ArgErr()
			}
			vp.Expression = d.Val()
		case "action":
			if !d.NextArg() {
				return d.ArgErr()
			}
			action := d.Val()
			switch action {
			case "allow":
				vp.Action = PolicyActionAllow
			case "deny":
				vp.Action = PolicyActionDeny
			default:
				return d.Errf("invalid action '%s', must be 'allow' or 'deny'", action)
			}
		default:
			return d.Errf("unknown directive: %s", d.Val())
		}
	}

	return nil
}

// Admit processes an admission review and evaluates the validation policy.
//
// Implements the [Controller] interface.
func (vp ValidationPolicy) Admit(
	ctx context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	input := map[string]any{
		"operation": string(review.Request.Operation),
	}

	if review.Request.Name != "" {
		input["name"] = review.Request.Name
	}

	if review.Request.Namespace != "" {
		input["requestNamespace"] = review.Request.Namespace
	}

	if review.Request.Object.Raw != nil {
		var obj unstructured.Unstructured

		if err := json.Unmarshal(review.Request.Object.Raw, &obj); err != nil {
			return nil, fmt.Errorf("unmarshaling object: %w", err)
		}

		input["object"] = obj.Object
	}

	if review.Request.OldObject.Raw != nil {
		var obj unstructured.Unstructured

		if err := json.Unmarshal(review.Request.OldObject.Raw, &obj); err != nil {
			return nil, fmt.Errorf("unmarshaling old object: %w", err)
		}

		input["oldObject"] = obj.Object
	}

	result, _, err := vp.program.ContextEval(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("evaluating CEL program: %w", err)
	}

	if result.Type() != cel.BoolType {
		return nil, fmt.Errorf("unexpected non-bool result of type %T", result.Value())
	}

	policyMatches := result.Value().(bool)

	// Allow if:
	// - policy matches and action is allow
	// - policy doesn't match
	allowed := (policyMatches && vp.Action == PolicyActionAllow) || !policyMatches

	return &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: allowed,
	}, nil
}

// Interface guards
var (
	_ Controller            = (*ValidationPolicy)(nil)
	_ caddy.Provisioner     = (*ValidationPolicy)(nil)
	_ caddyfile.Unmarshaler = (*ValidationPolicy)(nil)
)
