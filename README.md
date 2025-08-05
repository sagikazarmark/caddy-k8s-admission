# Caddy Kubernetes Admission Webhook

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sagikazarmark/caddy-k8s-admission/ci.yaml?style=flat-square)
![Caddy Version](https://img.shields.io/badge/caddy%20version-%3E=2.10.x-61CFDD.svg?style=flat-square)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/sagikazarmark/caddy-k8s-admission?style=flat-square&color=61CFDD)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/caddy-k8s-admission/badge?style=flat-square)](https://deps.dev/go/github.com%252Fsagikazarmark%252Fcaddy-k8s-admission)

**Caddy HTTP handler module for Kubernetes admission webhooks.**

This module provides a Caddy HTTP handler that can process Kubernetes admission webhook requests, making it easy to implement admission controllers using Caddy's powerful configuration system.

## Installation

Build Caddy using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/sagikazarmark/caddy-k8s-admission
```

## Usage

### Basic Example

```caddyfile
example.com {
    k8s_admission always_allow
}
```

### Annotation Injector

```caddyfile
example.com {
    k8s_admission annotation_injector {
        managed-by caddy-k8s-admission
        version v1.0.0
        environment production
    }
}
```

### Validation Policy

```caddyfile
example.com {
    k8s_admission validation_policy {
        expression "requestNamespace != 'kube-system'"
        action deny
    }
}
```

## Built-in Handlers

### `always_allow`

A simple handler that always allows admission requests. Useful for testing or as a default fallback.

```caddyfile
k8s_admission always_allow
```

### `always_deny`

A simple handler that always denies admission requests. Useful for testing or temporary blocking.

```caddyfile
k8s_admission always_deny
```

### `annotation_injector`

Injects specified annotations into Kubernetes resources using JSON Patch operations.

```caddyfile
k8s_admission annotation_injector {
    app.kubernetes.io/managed-by caddy-admission-webhook
    app.kubernetes.io/version v1.0.0
    custom.example.com/environment production
}
```

### `validation_policy`

Validates resources using CEL (Common Expression Language) expressions and takes configurable actions.

```caddyfile
# Deny pods in the kube-system namespace
k8s_admission validation_policy {
    expression "requestNamespace == 'kube-system'"
    action deny
}

# Allow only pods with specific naming convention
k8s_admission validation_policy {
    expression "name.startsWith('prod-')"
    action allow
}

# Complex validation with multiple conditions
k8s_admission validation_policy {
    expression "operation == 'CREATE' && requestNamespace == 'production' && has(object.metadata) && object.metadata.name.startsWith('critical-')"
    action deny
}
```

**Available Variables in CEL Expressions:**
- `name` - The resource name (string)
- `requestNamespace` - The resource namespace (string)
- `operation` - The admission operation (CREATE, UPDATE, DELETE)
- `object` - The current resource object (map)
- `oldObject` - The previous resource object for UPDATE operations (map)

**Actions:**
- `allow` - Allow the request when the expression matches
- `deny` - Deny the request when the expression matches

## Kubernetes Configuration

### ValidatingAdmissionWebhook

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: caddy-validator
webhooks:
- name: validator.example.com
  clientConfig:
    service:
      name: caddy-admission-webhook
      namespace: default
      path: "/validate"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
```

### MutatingAdmissionWebhook

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionWebhook
metadata:
  name: caddy-mutator
webhooks:
- name: mutator.example.com
  clientConfig:
    service:
      name: caddy-admission-webhook
      namespace: default
      path: "/mutate"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
```

## TLS Configuration

Admission webhooks require TLS. Here's an example Caddyfile with automatic HTTPS:

```caddyfile
{
    auto_https off
}

:8443 {
    tls /etc/certs/tls.crt /etc/certs/tls.key

    route /validate {
        k8s_admission always_allow
    }

    route /mutate {
        k8s_admission annotation_injector {
            app.kubernetes.io/managed-by caddy-admission-webhook
        }
    }
}
```

## Custom Handlers

You can create custom admission handlers by implementing the `Handler` interface:

```go
type Handler interface {
    Admit(ctx context.Context, review admissionv1.AdmissionReview) *admissionv1.AdmissionResponse
}
```

Register your custom handler as a Caddy module in the `k8s.admission` namespace:

```go
func init() {
    caddy.RegisterModule(MyCustomHandler{})
}

type MyCustomHandler struct {
    // Your configuration fields
}

func (MyCustomHandler) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "k8s.admission.my_custom_handler",
        New: func() caddy.Module { return new(MyCustomHandler) },
    }
}

func (h MyCustomHandler) Admit(ctx context.Context, review admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
    // Your admission logic here
    return &admissionv1.AdmissionResponse{
        UID:     review.Request.UID,
        Allowed: true,
    }
}
```

## Development

**For an optimal developer experience, it is recommended to install [Nix](https://nixos.org/download.html) and [direnv](https://direnv.net/docs/installation.html).**

Run tests:

```bash
just test
```

Run linters and formatters:

```bash
just lint
just fmt
```

Build the module:

```bash
just build
```

Alternatively, you can use standard Go commands if you have Go installed:

```bash
go test ./...
go build
```

## License

The project is licensed under the [MIT License](LICENSE).
