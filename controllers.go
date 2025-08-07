package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/cel-go/cel"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	caddy.RegisterModule(AlwaysAllow{})
	caddy.RegisterModule(AlwaysDeny{})
	caddy.RegisterModule(Validation{})
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

// ValidationReason represents the reason for validation failure.
type ValidationReason string

const (
	// ValidationReasonUnauthorized indicates the request is unauthorized.
	ValidationReasonUnauthorized ValidationReason = "Unauthorized"

	// ValidationReasonForbidden indicates the request is forbidden.
	ValidationReasonForbidden ValidationReason = "Forbidden"

	// ValidationReasonInvalid indicates the request is invalid.
	ValidationReasonInvalid ValidationReason = "Invalid"

	// ValidationReasonRequestEntityTooLarge indicates the request entity is too large.
	ValidationReasonRequestEntityTooLarge ValidationReason = "RequestEntityTooLarge"
)

// Validation is an admission webhook controller that validates resources using CEL expressions.
//
// It evaluates the provided expression against the resource. If the expression returns false, the request is denied.
type Validation struct {
	// Name is an optional name for the validation that can be referenced in CEL expressions as 'policyName'.
	// If no message or message_expression is specified and a request is denied, defaults to "Rejected by 'NAME' validation".
	Name string `json:"name,omitempty"`

	// Expression is the validation expression to evaluate against the resource.
	// If the expression returns false, the request is denied.
	Expression string `json:"expression,omitempty"`

	// Message is a static message to include in the admission response when the request is denied.
	Message string `json:"message,omitempty"`

	// MessageExpression is a CEL expression that returns a string message.
	// Takes precedence over Message if both are specified.
	MessageExpression string `json:"message_expression,omitempty"`

	// Reason is the reason for validation failure. Valid values: Unauthorized, Forbidden, Invalid, RequestEntityTooLarge.
	// Defaults to Invalid.
	Reason ValidationReason `json:"reason,omitempty"`

	program        cel.Program
	messageProgram cel.Program
}

// CaddyModule returns the Caddy module information.
func (Validation) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s.admission.validation",
		New: func() caddy.Module { return new(Validation) },
	}
}

// Provision sets up the validation.
func (v *Validation) Provision(_ caddy.Context) error {
	// Set default reason if not specified
	if v.Reason == "" {
		v.Reason = ValidationReasonInvalid
	}

	// Validate reason
	validReasons := map[ValidationReason]bool{
		ValidationReasonUnauthorized:          true,
		ValidationReasonForbidden:             true,
		ValidationReasonInvalid:               true,
		ValidationReasonRequestEntityTooLarge: true,
	}
	if !validReasons[v.Reason] {
		return fmt.Errorf("invalid reason '%s'", v.Reason)
	}

	env, err := cel.NewEnv(
		cel.Variable("name", cel.StringType),                                // optional
		cel.Variable("requestNamespace", cel.StringType),                    // optional
		cel.Variable("operation", cel.StringType),                           // required
		cel.Variable("object", cel.MapType(cel.StringType, cel.AnyType)),    // optional
		cel.Variable("oldObject", cel.MapType(cel.StringType, cel.AnyType)), // optional
		cel.Variable("policyName", cel.StringType),                          // optional
	)
	if err != nil {
		return fmt.Errorf("initializing CEL environment: %w", err)
	}

	ast, iss := env.Compile(v.Expression)
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

	v.program = program

	// Compile message expression if provided
	if v.MessageExpression != "" {
		messageAst, iss := env.Compile(v.MessageExpression)
		if iss.Err() != nil {
			return fmt.Errorf("compile CEL message expression: %w", iss.Err())
		}

		if !messageAst.OutputType().IsEquivalentType(cel.StringType) {
			return fmt.Errorf(
				"message expression must return string, got %v",
				messageAst.OutputType(),
			)
		}

		messageProgram, err := env.Program(messageAst)
		if err != nil {
			return fmt.Errorf("generating CEL message program: %w", err)
		}

		v.messageProgram = messageProgram
	}

	return nil
}

// UnmarshalCaddyfile implements [caddyfile.Unmarshaler].
func (v *Validation) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	// Check if there's an argument after the directive name (validation NAME)
	if d.NextArg() {
		v.Name = d.Val()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v.Name = d.Val()
		case "expression":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v.Expression = d.Val()
		case "message":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v.Message = d.Val()
		case "message_expression":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v.MessageExpression = d.Val()
		case "reason":
			if !d.NextArg() {
				return d.ArgErr()
			}
			reason := d.Val()
			switch reason {
			case "Unauthorized":
				v.Reason = ValidationReasonUnauthorized
			case "Forbidden":
				v.Reason = ValidationReasonForbidden
			case "Invalid":
				v.Reason = ValidationReasonInvalid
			case "RequestEntityTooLarge":
				v.Reason = ValidationReasonRequestEntityTooLarge
			default:
				return d.Errf(
					"invalid reason '%s', must be one of: Unauthorized, Forbidden, Invalid, RequestEntityTooLarge",
					reason,
				)
			}
		default:
			return d.Errf("unknown directive: %s", d.Val())
		}
	}

	return nil
}

// getReasonHTTPCode returns the appropriate HTTP status code for a validation reason.
func getReasonHTTPCode(reason ValidationReason) int32 {
	switch reason {
	case ValidationReasonUnauthorized:
		return http.StatusUnauthorized
	case ValidationReasonForbidden:
		return http.StatusForbidden
	case ValidationReasonInvalid:
		return http.StatusBadRequest
	case ValidationReasonRequestEntityTooLarge:
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusBadRequest
	}
}

// Admit processes an admission review and evaluates the validation expression.
//
// Implements the [Controller] interface.
func (v Validation) Admit(
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

	input["policyName"] = v.Name

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

	result, _, err := v.program.ContextEval(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("evaluating CEL program: %w", err)
	}

	if result.Type() != cel.BoolType {
		return nil, fmt.Errorf("unexpected non-bool result of type %T", result.Value())
	}

	// If expression returns false, deny the request
	allowed := result.Value().(bool)

	response := &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: allowed,
	}

	// If the request is denied, set up the status message and reason
	if !allowed {
		var message string

		// Message priority: message_expression > message > default with name
		if v.messageProgram != nil {
			// Use message expression
			messageResult, _, err := v.messageProgram.ContextEval(ctx, input)
			if err != nil {
				return nil, fmt.Errorf("evaluating CEL message program: %w", err)
			}

			if messageResult.Type() != cel.StringType {
				return nil, fmt.Errorf(
					"unexpected non-string message result of type %T",
					messageResult.Value(),
				)
			}

			message = messageResult.Value().(string)
		} else if v.Message != "" {
			// Use static message
			message = v.Message
		} else if v.Name != "" {
			// Use default message with validation name
			message = fmt.Sprintf("Rejected by '%s' validation", v.Name)
		}

		// Set status with reason and message
		response.Result = &metav1.Status{
			Code:    getReasonHTTPCode(v.Reason),
			Reason:  metav1.StatusReason(v.Reason),
			Message: message,
		}
	}

	return response, nil
}

// Interface guards
var (
	_ Controller            = (*Validation)(nil)
	_ caddy.Provisioner     = (*Validation)(nil)
	_ caddyfile.Unmarshaler = (*Validation)(nil)
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
