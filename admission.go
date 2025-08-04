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

// Handler is the interface that admission webhook handlers must implement.
//
// Guest modules in the k8s.admission namespace should implement this interface.
type Handler interface {
	// Admit processes an admission review and returns an admission response.
	Admit(ctx context.Context, review admissionv1.AdmissionReview) *admissionv1.AdmissionResponse
}

// Webhook is a Caddy HTTP handler that processes Kubernetes admission webhook requests.
//
// It acts as a host module that loads guest admission webhook handler modules.
type Webhook struct {
	// HandlerRaw holds the raw JSON configuration for the admission webhook handler module.
	HandlerRaw json.RawMessage `json:"handler,omitempty" caddy:"namespace=k8s.admission inline_key=handler_type"`

	// Handler is the loaded admission webhook handler module.
	Handler Handler `json:"-"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Webhook) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.k8s_admission",
		New: func() caddy.Module { return new(Webhook) },
	}
}

// Provision sets up the handler and loads the admission webhook handler module.
func (h *Webhook) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	if h.HandlerRaw == nil {
		return fmt.Errorf("admission webhook handler module is required")
	}

	val, err := ctx.LoadModule(h, "HandlerRaw")
	if err != nil {
		return fmt.Errorf("loading admission webhook handler module: %w", err)
	}

	h.Handler = val.(Handler)

	return nil
}

// Validate validates the configuration.
func (h Webhook) Validate() error {
	if h.Handler == nil {
		return fmt.Errorf("no admission webhook handler configured")
	}

	return nil
}

// ServeHTTP processes HTTP requests for Kubernetes admission webhooks.
func (h Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
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

	if review.Request == nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("missing admission request"))
	}

	logger := h.logger.With(zap.String("uid", string(review.Request.UID)))

	logger.Debug(
		"processing admission review",
		zap.String("kind", review.Request.Kind.String()),
		zap.String("operation", string(review.Request.Operation)),
	)

	// Process the admission review with the configured controller
	response := h.Handler.Admit(r.Context(), review)

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
func (h *Webhook) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	// Expect handler configuration
	if !d.NextArg() {
		return d.ArgErr()
	}

	handlerType := d.Val()

	// Create basic handler configuration
	handlerConfig := map[string]any{
		"handler_type": handlerType,
	}

	// Parse any additional configuration blocks
	for d.NextBlock(0) {
		key := d.Val()
		if !d.NextArg() {
			return d.ArgErr()
		}
		value := d.Val()
		handlerConfig[key] = value
	}

	// Marshal the configuration
	var err error
	h.HandlerRaw, err = json.Marshal(handlerConfig)
	if err != nil {
		return fmt.Errorf("marshaling admission webhook handler config: %v", err)
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new [Webhook].
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	admission := &Webhook{}
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
