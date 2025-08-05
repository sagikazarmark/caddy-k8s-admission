// Package admission provides a Caddy HTTP handler that processes Kubernetes admission webhook requests.
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
)

func init() {
	caddy.RegisterModule(Webhook{})
	httpcaddyfile.RegisterHandlerDirective("k8s_admission", parseCaddyfile)
}

// Controller is the interface that admission controllers must implement.
//
// Guest modules in the k8s.admission namespace should implement this interface.
type Controller interface {
	// Admit processes an admission review and returns an admission response.
	Admit(ctx context.Context, review admissionv1.AdmissionReview) *admissionv1.AdmissionResponse
}

// Webhook is a Caddy HTTP handler that processes Kubernetes admission webhook requests.
//
// It acts as a host module that loads guest modules admission controller modules.
type Webhook struct {
	// ControllerRaw holds the raw JSON configuration for the admission controller module.
	ControllerRaw json.RawMessage `json:"controller,omitempty" caddy:"namespace=k8s.admission inline_key=controller_type"`

	// Controller is the loaded admission controller module.
	Controller Controller `json:"-"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Webhook) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.k8s_admission",
		New: func() caddy.Module { return new(Webhook) },
	}
}

// Provision sets up the handler and loads the admission controller module.
func (wh *Webhook) Provision(ctx caddy.Context) error {
	wh.logger = ctx.Logger()

	if wh.ControllerRaw == nil {
		return fmt.Errorf("admission controller module is required")
	}

	val, err := ctx.LoadModule(wh, "ControllerRaw")
	if err != nil {
		return fmt.Errorf("loading admission controller module: %w", err)
	}

	wh.Controller = val.(Controller)

	return nil
}

// Validate validates the configuration.
func (wh Webhook) Validate() error {
	if wh.Controller == nil {
		return fmt.Errorf("no admission controller configured")
	}

	return nil
}

// ServeHTTP processes HTTP requests for Kubernetes admission webhooks.
func (wh Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
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
		wh.logger.Error("failed to decode admission review", zap.Error(err))

		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid admission review"))
	}

	if review.Request == nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("missing admission request"))
	}

	logger := wh.logger.With(zap.String("uid", string(review.Request.UID)))

	logger.Debug(
		"processing admission review",
		zap.String("kind", review.Request.Kind.String()),
		zap.String("operation", string(review.Request.Operation)),
	)

	// Process the admission review with the configured controller
	response := wh.Controller.Admit(r.Context(), review)

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

	logger.Debug("sending admission response", zap.Bool("allowed", response.Allowed))

	// Send the response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responseReview); err != nil {
		logger.Error("failed to encode admission response", zap.Error(err))

		return caddyhttp.Error(
			http.StatusInternalServerError,
			fmt.Errorf("failed to encode admission response"),
		)
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (wh *Webhook) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
	wh.ControllerRaw, err = json.Marshal(controllerConfig)
	if err != nil {
		return fmt.Errorf("marshaling admission controller config: %v", err)
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new [Webhook].
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	admission := new(Webhook)
	err := admission.UnmarshalCaddyfile(h.Dispenser)

	return admission, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Webhook)(nil)
	_ caddy.Validator             = (*Webhook)(nil)
	_ caddyhttp.MiddlewareHandler = (*Webhook)(nil)
	_ caddyfile.Unmarshaler       = (*Webhook)(nil)
)
