package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/cel-go/cel"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	caddy.RegisterModule(AlwaysAllow{})
	caddy.RegisterModule(AlwaysDeny{})
	caddy.RegisterModule(CelPolicy{})
	caddy.RegisterModule(JSONPatch{})
	caddy.RegisterModule(JSONPatches{})
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

// PolicyAction represents the action to take when a validation policy is matched.
type PolicyAction string

const (
	// PolicyActionAllow allows the request when the policy matches.
	PolicyActionAllow PolicyAction = "allow"

	// PolicyActionDeny denies the request when the policy matches.
	PolicyActionDeny PolicyAction = "deny"
)

// CelPolicy is an admission webhook controller that validates resources using CEL expressions.
//
// It evaluates the provided expression against the resource and takes the specified action.
type CelPolicy struct {
	// Expression is the validation expression to evaluate against the resource.
	Expression string `json:"expression,omitempty"`

	// Action is the action to take when the expression matches (allow or deny).
	Action PolicyAction `json:"action,omitempty"`

	program cel.Program
}

// CaddyModule returns the Caddy module information.
func (CelPolicy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.cel_policy",
		New: func() caddy.Module { return new(CelPolicy) },
	}
}

// Provision sets up the CEL policy.
func (vp *CelPolicy) Provision(_ caddy.Context) error {
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
func (vp *CelPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for nesting := d.Nesting(); d.NextBlock(nesting); {
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

// Admit processes an admission review and evaluates the CEL policy.
//
// Implements the [Controller] interface.
func (vp CelPolicy) Admit(
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
	_ Controller            = (*CelPolicy)(nil)
	_ caddy.Provisioner     = (*CelPolicy)(nil)
	_ caddyfile.Unmarshaler = (*CelPolicy)(nil)
)

// JSONPatch is an admission webhook controller that applies a single JSON Patch operation to resources.
//
// It applies one JSON Patch operation to incoming resources.
// Supports all standard JSON Patch operations: add, remove, replace, move, copy, test.
type JSONPatch struct {
	// Op is the operation to perform (add, remove, replace, move, copy, test).
	Op string `json:"op"`

	// Path is the JSON Pointer path where the operation should be applied.
	Path string `json:"path"`

	// Value is the value to use for the operation (not used for remove and test operations).
	Value any `json:"value,omitempty"`

	// From is the source path for move and copy operations.
	From string `json:"from,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (JSONPatch) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.json_patch",
		New: func() caddy.Module { return new(JSONPatch) },
	}
}

// Provision sets up the JSON patch operation.
func (p *JSONPatch) Provision(_ caddy.Context) error {
	return p.Validate()
}

// Validate validates a single JSON patch operation.
func (p JSONPatch) Validate() error {
	if p.Op == "" {
		return fmt.Errorf("operation is required")
	}

	validOps := map[string]bool{
		"add": true, "remove": true, "replace": true,
		"move": true, "copy": true, "test": true,
	}

	if !validOps[p.Op] {
		return fmt.Errorf("invalid operation '%s'", p.Op)
	}

	if p.Path == "" {
		return fmt.Errorf("path is required")
	}

	// Validate that move/copy operations have 'from' field
	if (p.Op == "move" || p.Op == "copy") && p.From == "" {
		return fmt.Errorf("'from' field is required for %s operation", p.Op)
	}

	// Validate that add/replace/test operations have 'value' field (except remove)
	if (p.Op == "add" || p.Op == "replace" || p.Op == "test") && p.Value == nil {
		return fmt.Errorf("'value' field is required for %s operation", p.Op)
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *JSONPatch) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if err := p.parsePatchDirective(d); err != nil {
			return err
		}
	}

	return nil
}

// parsePatchDirective parses a single patch directive.
func (p *JSONPatch) parsePatchDirective(d *caddyfile.Dispenser) error {
	switch d.Val() {
	case "op":
		if !d.NextArg() {
			return d.ArgErr()
		}
		p.Op = d.Val()
	case "path":
		if !d.NextArg() {
			return d.ArgErr()
		}
		p.Path = d.Val()
	case "value":
		if !d.NextArg() {
			return d.ArgErr()
		}

		// Handle multiple values as array
		values := []string{d.Val()}
		for d.NextArg() {
			values = append(values, d.Val())
		}

		var value any
		if len(values) == 1 {
			// Single value - try to parse as JSON, fallback to string
			if err := json.Unmarshal([]byte(values[0]), &value); err != nil {
				value = values[0]
			}
		} else {
			// Multiple values - create array, attempting JSON parse for each
			var parsedValues []any
			for _, v := range values {
				var parsed any
				if err := json.Unmarshal([]byte(v), &parsed); err != nil {
					parsed = v
				}
				parsedValues = append(parsedValues, parsed)
			}
			value = parsedValues
		}
		p.Value = value
	case "from":
		if !d.NextArg() {
			return d.ArgErr()
		}
		p.From = d.Val()
	default:
		return d.Errf("unknown directive: %s", d.Val())
	}

	return nil
}

// Admit processes an admission review and applies the configured JSON patch.
//
// Implements the [Controller] interface.
func (p JSONPatch) Admit(
	_ context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	// Convert patch to JSON
	patches := []JSONPatch{p}
	patch, err := json.Marshal(patches)
	if err != nil {
		return nil, fmt.Errorf("marshaling patch: %w", err)
	}

	patchType := admissionv1.PatchTypeJSONPatch

	return &admissionv1.AdmissionResponse{
		UID:       review.Request.UID,
		Allowed:   true,
		Patch:     patch,
		PatchType: &patchType,
	}, nil
}

// Interface guards
var (
	_ Controller            = (*JSONPatch)(nil)
	_ caddy.Provisioner     = (*JSONPatch)(nil)
	_ caddy.Validator       = (*JSONPatch)(nil)
	_ caddyfile.Unmarshaler = (*JSONPatch)(nil)
)

// JSONPatches is an admission webhook controller that applies custom JSON patches to resources.
//
// It accepts a list of JSON Patch operations and applies them to incoming resources.
// Supports all standard JSON Patch operations: add, remove, replace, move, copy, test.
type JSONPatches struct {
	// Patches is the list of JSON patch operations.
	Patches []JSONPatch `json:"patches,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (JSONPatches) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.json_patches",
		New: func() caddy.Module { return new(JSONPatches) },
	}
}

// Provision sets up the JSON patch controller.
func (j *JSONPatches) Provision(ctx caddy.Context) error {
	if j.Patches == nil {
		j.Patches = make([]JSONPatch, 0)
	}

	// Provision each patch
	for i, patch := range j.Patches {
		if err := patch.Provision(ctx); err != nil {
			return fmt.Errorf("provisioning patch %d: %w", i, err)
		}
		j.Patches[i] = patch
	}

	return nil
}

// Validate validates the configuration.
func (j JSONPatches) Validate() error {
	var errs []error

	for i, patch := range j.Patches {
		if err := patch.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("patch %d: %w", i, err))
		}
	}

	return errors.Join(errs...)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (j *JSONPatches) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if j.Patches == nil {
		j.Patches = make([]JSONPatch, 0)
	}

	d.Next()

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "patch":
			// Create a new JSONPatch and parse its content directly
			patch := new(JSONPatch)

			// Parse patch block content
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				if err := patch.parsePatchDirective(d); err != nil {
					return err
				}
			}

			j.Patches = append(j.Patches, *patch)
		default:
			return d.Errf("unknown directive: %s", d.Val())
		}
	}

	return nil
}

// Admit processes an admission review and applies the configured JSON patches.
//
// Implements the [Controller] interface.
func (j JSONPatches) Admit(
	_ context.Context,
	review admissionv1.AdmissionReview,
) (*admissionv1.AdmissionResponse, error) {
	// If no patches configured, allow without modification
	if len(j.Patches) == 0 {
		return &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: true,
		}, nil
	}

	// Convert patches to JSON
	patch, err := json.Marshal(j.Patches)
	if err != nil {
		return nil, fmt.Errorf("marshaling patches: %w", err)
	}

	patchType := admissionv1.PatchTypeJSONPatch

	return &admissionv1.AdmissionResponse{
		UID:       review.Request.UID,
		Allowed:   true,
		Patch:     patch,
		PatchType: &patchType,
	}, nil
}

// Interface guards
var (
	_ Controller            = (*JSONPatches)(nil)
	_ caddy.Provisioner     = (*JSONPatches)(nil)
	_ caddy.Validator       = (*JSONPatches)(nil)
	_ caddyfile.Unmarshaler = (*JSONPatches)(nil)
)
