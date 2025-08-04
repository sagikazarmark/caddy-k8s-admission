package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func init() {
	caddy.RegisterModule(Admission{})
	httpcaddyfile.RegisterHandlerDirective("k8s_admission", parseCaddyfile)
}

// Controller is the interface that admission webhook handlers must implement.
//
// Guest modules in the k8s.admission namespace should implement this interface.
type Controller interface {
	// Admit processes an admission review and returns an admission response.
	Admit(ctx context.Context, review admissionv1.AdmissionReview) *admissionv1.AdmissionResponse
}

// Admission is a Caddy HTTP handler that processes Kubernetes admission webhook requests.
//
// It acts as a host module that loads guest admission controller modules.
type Admission struct {
	// ControllerRaw holds the raw JSON configuration for the admission controller module.
	ControllerRaw json.RawMessage `json:"controller,omitempty" caddy:"namespace=k8s.admission inline_key=controller_type"`

	// Controller is the loaded admission controller module.
	Controller Controller `json:"-"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Admission) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.k8s_admission",
		New: func() caddy.Module { return new(Admission) },
	}
}

// Provision sets up the handler and loads the admission controller module.
func (h *Admission) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	if h.ControllerRaw == nil {
		return fmt.Errorf("admission controller module is required")
	}

	val, err := ctx.LoadModule(h, "ControllerRaw")
	if err != nil {
		return fmt.Errorf("loading admission controller module: %w", err)
	}

	h.Controller = val.(Controller)

	return nil
}

// Validate validates the configuration.
func (h Admission) Validate() error {
	if h.Controller == nil {
		return fmt.Errorf("no admission controller configured")
	}

	return nil
}

// ServeHTTP processes HTTP requests for Kubernetes admission webhooks.
func (h Admission) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Check if this looks like an admission webhook request
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid content type"))
	}

	// Parse the admission review
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		h.logger.Error("failed to decode admission review", zap.Error(err))

		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid admission review"))
	}

	logger := h.logger.With(zap.String("uid", string(review.Request.UID)))

	logger.Debug(
		"processing admission review",
		zap.String("kind", review.Request.Kind.String()),
		zap.String("operation", string(review.Request.Operation)),
	)

	// Process the admission review with the configured controller
	response := h.Controller.Admit(r.Context(), review)

	// Ensure the response has the correct UID
	if response != nil {
		response.UID = review.Request.UID
	} else {
		logger.Warn("admission controller returned no response")

		// If no response is provided, create a default allow response
		response = &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: true,
		}
	}

	// Create the response admission review
	responseReview := admissionv1.AdmissionReview{
		TypeMeta: review.TypeMeta,
		Response: response,
	}

	logger.Debug(
		"sending admission response",
		zap.Bool("allowed", response.Allowed),
	)

	// Send the response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responseReview); err != nil {
		logger.Error("failed to encode admission response", zap.Error(err))

		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to encode admission response"))
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Admission) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	// Expect controller configuration
	if !d.NextArg() {
		return d.ArgErr()
	}

	controllerType := d.Val()

	// Create basic controller configuration
	controllerConfig := map[string]any{
		"controller_type": controllerType,
	}

	// Parse any additional configuration blocks
	for d.NextBlock(0) {
		key := d.Val()
		if !d.NextArg() {
			return d.ArgErr()
		}
		value := d.Val()
		controllerConfig[key] = value
	}

	// Marshal the configuration
	var err error
	h.ControllerRaw, err = json.Marshal(controllerConfig)
	if err != nil {
		return fmt.Errorf("marshaling admission controller config: %v", err)
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new [Admission].
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var admission Admission
	err := admission.UnmarshalCaddyfile(h.Dispenser)
	return admission, err
}

// AllowResponse creates a simple allow response for admission reviews.
func AllowResponse(uid string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     types.UID(uid),
		Allowed: true,
	}
}

// DenyResponse creates a deny response with a message for admission reviews.
func DenyResponse(uid, message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     types.UID(uid),
		Allowed: false,
		Result: &metav1.Status{
			Code:    http.StatusForbidden,
			Message: message,
		},
	}
}

// PatchResponse creates a response with JSON patches for mutating admission webhooks.
func PatchResponse(uid string, patches []byte) *admissionv1.AdmissionResponse {
	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		UID:       types.UID(uid),
		Allowed:   true,
		Patch:     patches,
		PatchType: &patchType,
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Admission)(nil)
	_ caddy.Validator             = (*Admission)(nil)
	_ caddyhttp.MiddlewareHandler = (*Admission)(nil)
	_ caddyfile.Unmarshaler       = (*Admission)(nil)
)
