# Kubernetes Upgrade Feasibility, Compatibility, and Risk Assessment Tool

This project provides a lightweight assessment engine that turns Kubernetes cluster inventory data into a structured upgrade-readiness review matching the requirements in `prompt.md`.

## What it does

- Accepts cluster-export JSON containing the core inventory sections from the prompt
- Evaluates API, CRD, controller, webhook, networking, storage, security, runtime, and node upgrade risk
- Produces a Markdown assessment report with:
  - risk matrix
  - readiness score
  - confidence score
  - executive summary
  - mandatory breakage declaration
  - verified/probable/possible/unknown risk sections

## Example usage

```bash
C:/Python314/python.exe -m kubernetes_upgrade_assessor \
  --source-version 1.25 \
  --target-version 1.29 \
  --input examples/sample_cluster_data.json
```

The command writes a report to stdout by default. Use `--output report.md` to save it to disk.

## Input shape

The tool expects JSON shaped like this:

```json
{
  "cluster_info": {
    "kubernetes_version": "v1.25.16",
    "managed_cluster": true,
    "ha_topology": "3 control plane / 5 workers",
    "api_server_version": "v1.25.16",
    "node_versions": ["v1.25.15", "v1.25.15"]
  },
  "workloads": [
    {
      "namespace": "prod",
      "kind": "Deployment",
      "name": "api",
      "api_version": "apps/v1",
      "criticality": "high"
    }
  ],
  "crds": [
    {
      "name": "prometheuses.monitoring.coreos.com",
      "served_versions": ["v1"],
      "storage_version": "v1",
      "conversion_strategy": "None",
      "api_compatibility": "pass"
    }
  ],
  "controllers": [
    {
      "name": "cert-manager",
      "version": "v1.13.3",
      "supported_kubernetes_versions": ["1.27", "1.28"],
      "status": "warning"
    }
  ],
  "admission_webhooks": [
    {
      "name": "policy-webhook",
      "failure_policy": "Fail",
      "tls_ready": true,
      "version_support": "v1"
    }
  ],
  "networking": {
    "status": "warning",
    "notes": "Ingress controller is on a legacy chart version."
  },
  "storage": {
    "status": "high-risk",
    "notes": "CSI driver compatibility needs validation."
  },
  "security": {
    "status": "warning",
    "notes": "Pod Security Admission is enforcing restricted policies."
  },
  "runtime": {
    "status": "pass",
    "container_runtime": "containerd",
    "runtime_version": "1.7.11"
  },
  "resource_pressure": {
    "status": "warning",
    "notes": "Cluster is CPU constrained during peak hours."
  }
}
```

## Notes

This is intentionally conservative. If compatibility cannot be confirmed from the supplied evidence, the tool marks the area as a risk and lowers confidence accordingly.
