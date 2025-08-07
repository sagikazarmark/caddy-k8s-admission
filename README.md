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

### Validation

```caddyfile
example.com {
    k8s_admission validation {
        expression "requestNamespace == 'kube-system'"
    }
}
```

### JSON Patch

```caddyfile
example.com {
    k8s_admission json_patches {
        patch {
            op "add"
            path "/metadata/labels/managed-by"
            value "caddy-admission-webhook"
        }
        patch {
            op "replace"
            path "/spec/replicas"
            value 3
        }
    }
}
```

## Built-in Controllers

### `always_allow`

A simple controller that always allows admission requests. Useful for testing or as a default fallback.

```caddyfile
k8s_admission always_allow
```

### `always_deny`

A simple controller that always denies admission requests. Useful for testing or temporary blocking.

```caddyfile
k8s_admission always_deny
```

### `validation`

Validates resources using CEL (Common Expression Language) expressions. If the expression returns `false`, the request is denied.

```caddyfile
# Deny pods in the kube-system namespace
k8s_admission validation {
    expression "requestNamespace != 'kube-system'"
}

# Allow only pods with specific naming convention
k8s_admission validation {
    expression "name.startsWith('prod-')"
}

# Complex validation with multiple conditions
k8s_admission validation {
    expression "!(operation == 'CREATE' && requestNamespace == 'production' && has(object.metadata) && object.metadata.name.startsWith('critical-'))"
}

# Validation with custom message and reason
k8s_admission validation {
    name "security-policy"
    expression "requestNamespace != 'kube-system'"
    message "kube-system namespace is protected"
    reason Forbidden
}

# Validation with dynamic message expression
k8s_admission validation {
    expression "operation != 'DELETE'"
    message_expression "'Cannot delete ' + object.kind + ' resources in ' + requestNamespace"
    reason Unauthorized
}
```

**Available Variables in CEL Expressions:**
- `name` - The resource name (string)
- `requestNamespace` - The resource namespace (string)
- `operation` - The admission operation (CREATE, UPDATE, DELETE)
- `object` - The current resource object (map)
- `oldObject` - The previous resource object for UPDATE operations (map)
- `policyName` - The validation name (string)

**Configuration Options:**
- `name` - Optional name for the validation (can be referenced as `policyName` in expressions)
- `expression` - CEL expression that must return `true` for the request to be allowed
- `message` - Static message to include when the request is denied
- `message_expression` - CEL expression that returns a dynamic message (takes precedence over `message`)
- `reason` - Reason for denial: `Unauthorized`, `Forbidden`, `Invalid` (default), `RequestEntityTooLarge`

### `json_patch`

Applies a single JSON Patch operation to Kubernetes resources. Supports all standard JSON Patch operations: add, remove, replace, move, copy, and test.

```caddyfile
# Add a single label
k8s_admission json_patch {
    op "add"
    path "/metadata/labels/managed-by"
    value "caddy-admission-webhook"
}

# Remove an annotation
k8s_admission json_patch {
    op "remove"
    path "/metadata/annotations/unwanted-annotation"
}

# Replace resource limits
k8s_admission json_patch {
    op "replace"
    path "/spec/template/spec/containers/0/resources"
    value {"limits":{"memory":"512Mi","cpu":"500m"},"requests":{"memory":"256Mi","cpu":"250m"}}
}

# Move a label
k8s_admission json_patch {
    op "move"
    path "/metadata/labels/new-label"
    from "/metadata/labels/old-label"
}
```

### `json_patches`

Applies multiple JSON Patch operations to Kubernetes resources. Supports all standard JSON Patch operations: add, remove, replace, move, copy, and test.

```caddyfile
# Add labels and modify replicas
k8s_admission json_patches {
    patch {
        op "add"
        path "/metadata/labels/app"
        value "my-app"
    }
    patch {
        op "replace"
        path "/spec/replicas"
        value 3
    }
}

# Add environment variables with JSON object
k8s_admission json_patches {
    patch {
        op "add"
        path "/spec/template/spec/containers/0/env/-"
        value {"name":"DATABASE_URL","value":"postgres://..."}
    }
}

# Add multiple ports using array syntax
k8s_admission json_patches {
    patch {
        op "add"
        path "/spec/template/spec/containers/0/ports"
        value 8080 8443 9090
    }
}

# Move and copy operations
k8s_admission json_patches {
    patch {
        op "move"
        path "/metadata/labels/new-label"
        from "/metadata/labels/old-label"
    }
    patch {
        op "copy"
        path "/metadata/annotations/backup-of-label"
        from "/metadata/labels/important-label"
    }
}

# Remove unwanted fields
k8s_admission json_patches {
    patch {
        op "remove"
        path "/metadata/annotations/unwanted-annotation"
    }
}
```

**Supported Value Types:**
- **Strings**: `value "my-app"`
- **Numbers**: `value 3` (parsed as JSON numbers)
- **Booleans**: `value true` or `value false`
- **JSON Objects**: `value {"key":"value","nested":{"data":true}}`
- **Arrays from multiple arguments**: `value 8080 8443 9090` creates `[8080, 8443, 9090]`
- **Mixed arrays**: `value "string" 42 true {"key":"value"}`

**JSON Patch Operations:**
- `add` - Add a value at the specified path
- `remove` - Remove the value at the specified path
- `replace` - Replace the value at the specified path
- `move` - Move a value from one path to another
- `copy` - Copy a value from one path to another
- `test` - Test that the value at the path matches the specified value

## Examples

For comprehensive examples and configuration patterns, see the [`examples.Caddyfile`](examples.Caddyfile) file which contains:

- **Basic Controllers**: Simple allow/deny configurations
- **Operation-based Validation**: CREATE/UPDATE/DELETE operation filtering
- **Namespace-based Policies**: Whitelist/blacklist namespace patterns
- **Resource-based Validation**: Naming conventions, labels, security contexts
- **Complex Validation Logic**: Multi-condition CEL expressions
- **JSON Patch Mutations**: Label injection, security hardening, resource limits
- **Advanced Configurations**: Multi-stage validation, conditional patching
- **Testing & Debugging**: Health checks, metrics, debug logging

Each example includes detailed comments explaining the use case and configuration.

## Complete Example

Here's a comprehensive example showing multiple controllers working together:

```caddyfile
{
    auto_https off
}

:8443 {
    tls /etc/certs/tls.crt /etc/certs/tls.key

    # Validation endpoint - deny pods in kube-system
    route /validate {
        k8s_admission validation {
            expression "requestNamespace != 'kube-system'"
            reason Forbidden
        }
    }

    # Mutation endpoint - inject labels and modify resources
    route /mutate {
        k8s_admission json_patches {
            # Add management labels
            patch {
                op "add"
                path "/metadata/labels/managed-by"
                value "caddy-admission-webhook"
            }
            patch {
                op "add"
                path "/metadata/labels/version"
                value "v1.0.0"
            }

            # Add security context if not present
            patch {
                op "add"
                path "/spec/template/spec/securityContext"
                value {"runAsNonRoot":true,"runAsUser":1001}
            }

            # Add resource limits
            patch {
                op "add"
                path "/spec/template/spec/containers/0/resources"
                value {"limits":{"memory":"512Mi","cpu":"500m"},"requests":{"memory":"256Mi","cpu":"250m"}}
            }
        }
    }

    # Single patch endpoint - adds just one label
    route /patch {
        k8s_admission json_patch {
            op "add"
            path "/metadata/labels/single-patch"
            value "applied"
        }
    }

    # Testing endpoints
    route /test/allow {
        k8s_admission always_allow
    }

    route /test/deny {
        k8s_admission always_deny
    }
}
```

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
        k8s_admission json_patches {
            patch {
                op "add"
                path "/metadata/labels/managed-by"
                value "caddy-admission-webhook"
            }
        }
    }
}
```

## Custom Controllers

You can create custom admission controllers by implementing the `Controller` interface:

```go
type Controller interface {
    Admit(ctx context.Context, review admissionv1.AdmissionReview) *admissionv1.AdmissionResponse
}
```

Register your custom controller as a Caddy module in the `k8s.admission` namespace:

```go
func init() {
    caddy.RegisterModule(MyCustomController{})
}

type MyCustomController struct {
    // Your configuration fields
}

func (MyCustomController) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "k8s.admission.my_custom_controller",
        New: func() caddy.Module { return new(MyCustomController) },
    }
}

func (h MyCustomController) Admit(ctx context.Context, review admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
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
