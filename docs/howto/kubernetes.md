# Deploying on Kubernetes

Reference manifests for running the MCP proxy in a Kubernetes cluster.

## Quick start

```bash
# Review and customize the manifests
ls deploy/kubernetes/

# Apply everything
kubectl apply -k deploy/kubernetes/
```

This creates:

- `mcp` namespace
- `mcp-proxy` Deployment (1 replica)
- `mcp-proxy` ClusterIP Service on port 8080
- `mcp-config` ConfigMap with your server configuration
- `mcp-secrets` Secret for API tokens

## Configuration

### Server config via ConfigMap

Edit `deploy/kubernetes/configmap.yaml` with your MCP servers:

```yaml
data:
  servers.json: |
    {
      "mcpServers": {
        "sentry": {
          "url": "https://mcp.sentry.dev/sse",
          "headers": {
            "Authorization": "Bearer ${SENTRY_TOKEN}"
          }
        },
        "grafana": {
          "url": "https://grafana.internal/api/mcp/sse",
          "headers": {
            "Authorization": "Bearer ${GRAFANA_TOKEN}"
          }
        }
      }
    }
```

The proxy resolves `${VAR}` placeholders from environment variables at startup. This keeps tokens out of the ConfigMap.

### Secrets for tokens

Create the secret with your real tokens:

```bash
kubectl -n mcp create secret generic mcp-secrets \
  --from-literal=sentry-token=sntrys_abc123 \
  --from-literal=grafana-token=glsa_xyz789
```

Then reference each token in the Deployment env:

```yaml
env:
  - name: SENTRY_TOKEN
    valueFrom:
      secretKeyRef:
        name: mcp-secrets
        key: sentry-token
  - name: GRAFANA_TOKEN
    valueFrom:
      secretKeyRef:
        name: mcp-secrets
        key: grafana-token
```

### Pinning the image version

Edit `deploy/kubernetes/kustomization.yaml`:

```yaml
images:
  - name: ghcr.io/avelino/mcp
    newTag: "0.5.0"  # pin to a specific version
```

## Why `--insecure`?

The proxy refuses to bind non-loopback addresses without `--insecure`. In Kubernetes, the pod needs `0.0.0.0:8080` so the Service can route traffic to it. TLS termination happens at the Ingress or load balancer level, not at the proxy.

## Health probes

The proxy exposes `GET /health` returning:

```json
{
  "status": "ok",
  "backends_configured": 3,
  "backends_connected": 2,
  "active_clients": 5,
  "tools": 42,
  "version": "0.5.0"
}
```

### Why the probes are configured this way

**Startup probe** — gives 30s (`failureThreshold: 6 * periodSeconds: 5`) for the process to start and begin backend discovery. Discovery is async, so the proxy serves immediately but backends connect in the background.

**Liveness probe** — checks every 30s that the process responds to HTTP. Backend failures are **degraded state**, not a reason to restart the pod. If sentry is down, the proxy still serves grafana tools fine.

**Readiness probe** — checks every 10s. The proxy is ready to serve as soon as it starts because it lazy-connects backends on first request. A probe failure here means the process itself is unhealthy.

> **Do not** use `backends_connected > 0` as a readiness condition. The proxy is designed to start with zero connections and connect on demand.

## Audit logging

By default, audit logging is disabled (`MCP_AUDIT_ENABLED=false`) because the scratch-based image has no writable filesystem.

To enable:

1. Set `MCP_AUDIT_ENABLED=true` in the Deployment env
2. Mount persistent storage at `/data`:

```yaml
# In deployment.yaml, replace the emptyDir volume:
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: mcp-audit-data
```

3. Uncomment `pvc.yaml` in `kustomization.yaml`:

```yaml
resources:
  # ...
  - pvc.yaml
```

4. Apply:

```bash
kubectl apply -k deploy/kubernetes/
```

Audit logs are written to `/data/audit/data` and indexed at `/data/audit/index` (controlled by `MCP_AUDIT_PATH` and `MCP_AUDIT_INDEX_PATH`).

## Security context

The manifests include a hardened security context:

```yaml
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

The image is based on `scratch` — a static binary with no shell, no package manager, no libc. The process runs as UID 0 because scratch has no `/etc/passwd` to define other users. Despite running as root, the attack surface is minimal: no shell to exec into, no tools to exploit, read-only filesystem.

If your cluster policy requires `runAsNonRoot: true`, you'd need a non-scratch base image with a dedicated user.

## Scaling

Each replica is fully independent — own backend pool, own tool cache, own connections. There's no shared state, no leader election, no coordination needed.

Scaling to N replicas means:

- N independent connections to each backend
- N copies of the tool/resource/prompt cache in memory
- Clients are load-balanced across replicas by the Service

This is fine for most deployments. Be aware that stdio-based backends (which spawn child processes) will have N copies of each process running across the cluster.

## Graceful shutdown

When Kubernetes sends `SIGTERM` (during rolling updates or scale-down):

1. The proxy stops accepting new connections
2. In-flight requests finish normally
3. Backend clients are shut down in parallel (5s timeout each)
4. Total internal cleanup is bounded to ~10s

`terminationGracePeriodSeconds: 30` in the Deployment gives enough headroom. After 30s, Kubernetes sends `SIGKILL`.

## Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SERVERS_CONFIG` | — | Inline JSON config (highest priority) |
| `MCP_PROXY_REQUEST_TIMEOUT` | `120` | Max seconds per JSON-RPC request |
| `MCP_AUDIT_ENABLED` | `false` (in Docker) | Enable audit logging |
| `MCP_AUDIT_PATH` | `/data/audit/data` | Audit data directory |
| `MCP_AUDIT_INDEX_PATH` | `/data/audit/index` | Audit index directory |
| `MCP_CLASSIFIER_CACHE` | `/tmp/tool-classification.json` | Tool classification cache |

Full reference: [Environment variables](../reference/environment-variables.md)

## Exposing outside the cluster

The Service is `ClusterIP` by default. To expose externally, add an Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mcp-proxy
  namespace: mcp
  annotations:
    # TLS termination at the ingress
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts: ["mcp.example.com"]
      secretName: mcp-tls
  rules:
    - host: mcp.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: mcp-proxy
                port:
                  name: http
```

## Troubleshooting

### Pod starts but backends never connect

Check the ConfigMap config is valid JSON:

```bash
kubectl -n mcp get configmap mcp-config -o jsonpath='{.data.servers\.json}' | jq .
```

Check the proxy logs:

```bash
kubectl -n mcp logs deploy/mcp-proxy
```

Look for `[serve] discovering tools from ...` lines. If you see `failed to discover`, the backend URL or token is wrong.

### Health probe fails on startup

Increase the startup probe threshold:

```yaml
startupProbe:
  failureThreshold: 12  # 60s instead of 30s
  periodSeconds: 5
```

### Token not resolving

Ensure the Secret key matches what the Deployment env references, and that the `${VAR_NAME}` in the ConfigMap matches the env var name exactly. The proxy logs a warning if a placeholder can't be resolved.

### Read-only filesystem errors

If you see permission errors, make sure the `tmp` and `data` volumes are mounted. The scratch image has no writable paths without explicit volume mounts.
