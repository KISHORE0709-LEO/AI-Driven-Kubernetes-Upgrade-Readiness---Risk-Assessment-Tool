from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

STATUS_ORDER = {"pass": 0, "good": 1, "warning": 2, "high-risk": 3, "critical": 4}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DOMAIN_NAMES = [
    "APIs",
    "CRDs",
    "Controllers",
    "Webhooks",
    "Networking",
    "Storage",
    "Security",
    "Runtime",
    "Nodes",
    "Control Plane",
]


def safe_lower(value: Any) -> str:
    return str(value).strip().lower() if value is not None else ""


def normalize_status(value: Any) -> str:
    cleaned = safe_lower(value)
    mapping = {
        "pass": "pass",
        "good": "good",
        "warning": "warning",
        "high risk": "high-risk",
        "high-risk": "high-risk",
        "critical": "critical",
        "not recommended": "critical",
        "unknown": "warning",
    }
    return mapping.get(cleaned, cleaned or "warning")


def normalize_severity(value: Any) -> str:
    cleaned = safe_lower(value)
    mapping = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get(cleaned, cleaned or "medium")


def is_deprecated_api(api_version: str) -> bool:
    deprecated_tokens = ("beta", "v1beta", "v2beta", "extensions/v1beta1", "admissionregistration.k8s.io/v1beta1")
    return any(token in api_version.lower() for token in deprecated_tokens)


def _status_from_domain(domain: str, entry: Dict[str, Any]) -> Tuple[str, str]:
    if isinstance(entry, dict):
        status = normalize_status(entry.get("status") or entry.get("risk"))
        notes = entry.get("notes") or entry.get("remarks") or entry.get("summary") or "No specific evidence provided."
        return status, str(notes)
    return "warning", f"No evidence supplied for {domain}."


def _upgrade_decision(score: int) -> str:
    if score >= 90:
        return "APPROVED"
    if score >= 75:
        return "CONDITIONAL"
    if score >= 50:
        return "NOT RECOMMENDED"
    return "NOT RECOMMENDED"


def _update_area_status(areas: Dict[str, Dict[str, str]], domain: str, status: str, explanation: str) -> None:
    current = areas.get(domain, {"Status": "pass", "Severity": "low", "Explanation": "No issues detected."})
    current_status = normalize_status(current.get("Status"))
    if STATUS_ORDER.get(status, 0) > STATUS_ORDER.get(current_status, 0):
        current["Status"] = status.upper() if status.upper() in {"PASS", "GOOD", "WARNING", "HIGH-RISK", "CRITICAL"} else status
        current["Severity"] = {
            "pass": "Low",
            "good": "Low",
            "warning": "Medium",
            "high-risk": "High",
            "critical": "Critical",
        }.get(status, "Medium")
        current["Explanation"] = explanation
    areas[domain] = current


def _domain_key(name: str) -> str:
    return {
        "apis": "APIs",
        "crds": "CRDs",
        "controllers": "Controllers",
        "webhooks": "Webhooks",
        "networking": "Networking",
        "storage": "Storage",
        "security": "Security",
        "runtime": "Runtime",
        "nodes": "Nodes",
        "control plane": "Control Plane",
    }.get(name.lower(), name)


def _build_issues(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []

    cluster = data.get("cluster_info") or {}
    if not cluster:
        issues.append({
            "category": "Unknown",
            "severity": "medium",
            "status": "possible",
            "title": "Cluster inventory missing",
            "details": "No cluster metadata was supplied; upgrade confidence cannot be fully validated.",
        })

    for workload in data.get("workloads") or []:
        api_version = str(workload.get("api_version") or "")
        if is_deprecated_api(api_version):
            issues.append({
                "category": "APIs",
                "severity": "high",
                "status": "verified",
                "title": f"Deprecated API in {workload.get('namespace')}/{workload.get('name')}",
                "details": f"Workload {workload.get('namespace')}/{workload.get('name')} uses {api_version}; this API may be removed or have incompatible behavior in the target release.",
            })

    for crd in data.get("crds") or []:
        served = ", ".join(str(version) for version in (crd.get("served_versions") or []))
        storage = str(crd.get("storage_version") or "")
        if "v1beta1" in served.lower() or "v1beta1" in storage.lower():
            issues.append({
                "category": "CRDs",
                "severity": "high",
                "status": "verified",
                "title": f"CRD still serving beta storage: {crd.get('name')}",
                "details": f"CRD {crd.get('name')} is still serving or storing v1beta1 objects, which is likely incompatible with a Kubernetes upgrade without migration.",
            })
        elif crd.get("api_compatibility") == "warning":
            issues.append({
                "category": "CRDs",
                "severity": "medium",
                "status": "probable",
                "title": f"CRD compatibility needs validation: {crd.get('name')}",
                "details": crd.get("remarks") or "The CRD has compatibility warnings that need evidence before the upgrade proceeds.",
            })

    for controller in data.get("controllers") or []:
        status = normalize_status(controller.get("status"))
        supported = controller.get("supported_kubernetes_versions") or []
        if status in {"high-risk", "critical"} or (supported and not any("1.29" in str(s) or "1.28" in str(s) for s in supported)):
            issues.append({
                "category": "Controllers",
                "severity": "high" if status in {"high-risk", "critical"} else "medium",
                "status": "verified" if status in {"high-risk", "critical"} else "probable",
                "title": f"Controller compatibility issue: {controller.get('name')}",
                "details": f"{controller.get('name')} version {controller.get('version')} is not clearly supported for the target cluster version. {controller.get('notes') or 'Operator compatibility needs direct validation.'}",
            })

    for webhook in data.get("admission_webhooks") or []:
        if webhook.get("tls_ready") is False or webhook.get("status") in {"warning", "high-risk", "critical"}:
            issues.append({
                "category": "Webhooks",
                "severity": "high" if webhook.get("status") in {"high-risk", "critical"} else "medium",
                "status": "verified" if webhook.get("tls_ready") is False else "probable",
                "title": f"Admission webhook risk: {webhook.get('name')}",
                "details": webhook.get("notes") or "The webhook may fail during or after the upgrade and block workloads or admission requests.",
            })

    networking = data.get("networking") or {}
    if networking.get("status") in {"warning", "high-risk", "critical"}:
        issues.append({
            "category": "Networking",
            "severity": "medium" if normalize_status(networking.get("status")) == "warning" else "high",
            "status": "probable",
            "title": "Networking compatibility risk",
            "details": networking.get("notes") or "Ingress or CNI compatibility needs validation before the upgrade.",
        })

    storage = data.get("storage") or {}
    if storage.get("status") in {"warning", "high-risk", "critical"}:
        issues.append({
            "category": "Storage",
            "severity": "high" if normalize_status(storage.get("status")) in {"high-risk", "critical"} else "medium",
            "status": "probable",
            "title": "Storage compatibility risk",
            "details": storage.get("notes") or "CSI drivers or snapshot support may not be validated for the target version.",
        })

    security = data.get("security") or {}
    if security.get("status") in {"warning", "high-risk", "critical"}:
        issues.append({
            "category": "Security",
            "severity": "medium",
            "status": "probable",
            "title": "Security policy enforcement risk",
            "details": security.get("notes") or "Security changes may block workloads or require remediation before upgrade.",
        })

    runtime = data.get("runtime") or {}
    runtime_status = normalize_status(runtime.get("status"))
    if runtime_status in {"warning", "high-risk", "critical"}:
        issues.append({
            "category": "Runtime",
            "severity": "medium",
            "status": "probable",
            "title": "Runtime compatibility risk",
            "details": runtime.get("notes") or "Container runtime or kernel compatibility could interrupt node upgrades.",
        })

    pressure = data.get("resource_pressure") or {}
    if pressure.get("status") in {"warning", "high-risk", "critical"}:
        issues.append({
            "category": "Nodes",
            "severity": "medium",
            "status": "probable",
            "title": "Resource pressure during upgrade",
            "details": pressure.get("notes") or "The cluster has resource pressure and may trigger evictions or scheduling failures during upgrade operations.",
        })

    if not issues:
        issues.append({
            "category": "General",
            "severity": "low",
            "status": "possible",
            "title": "No explicit incompatibilities detected from supplied evidence",
            "details": "This assessment is based on the provided inventory only and should be validated against the real cluster state before upgrading.",
        })

    return issues


def _compute_score(areas: Dict[str, Dict[str, str]], issues: List[Dict[str, Any]], missing: int) -> Tuple[int, int]:
    penalty = 0
    for domain in DOMAIN_NAMES:
        area = areas.get(domain, {"Status": "pass", "Severity": "low"})
        status = normalize_status(area.get("Status"))
        penalty += {"pass": 0, "good": 3, "warning": 12, "high-risk": 25, "critical": 38}.get(status, 10)

    for issue in issues:
        if issue["category"] == "General":
            continue
        severity = normalize_severity(issue["severity"])
        penalty += {"low": 2, "medium": 7, "high": 15, "critical": 25}.get(severity, 5)

    readiness = max(0, 100 - penalty)
    confidence = 100 - max(0, missing * 12)
    unknowns = sum(1 for issue in issues if issue["status"] == "possible")
    confidence = max(0, confidence - (unknowns * 10))
    return readiness, confidence


def assess_cluster(data: Dict[str, Any], source_version: str, target_version: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise TypeError("Cluster data must be a dictionary")

    areas: Dict[str, Dict[str, str]] = {
        "APIs": {"Status": "pass", "Severity": "Low", "Explanation": "No critical API removals were identified in the supplied inventory."},
        "CRDs": {"Status": "pass", "Severity": "Low", "Explanation": "CRDs are assumed compatible unless explicitly flagged by the supplied inventory."},
        "Controllers": {"Status": "pass", "Severity": "Low", "Explanation": "Controllers appear compatible if their support matrix and release notes were documented."},
        "Webhooks": {"Status": "pass", "Severity": "Low", "Explanation": "Webhooks were not identified as blocking admission risk."},
        "Networking": {"Status": "pass", "Severity": "Low", "Explanation": "Networking is assumed compatible unless explicit incompatibility or pressure is noted."},
        "Storage": {"Status": "pass", "Severity": "Low", "Explanation": "Storage is assumed compatible unless explicit CSI or snapshot issues were noted."},
        "Security": {"Status": "pass", "Severity": "Low", "Explanation": "Security posture is assumed compatible unless policy changes were identified."},
        "Runtime": {"Status": "pass", "Severity": "Low", "Explanation": "Runtime is assumed compatible if node and container runtime evidence is current."},
        "Nodes": {"Status": "pass", "Severity": "Low", "Explanation": "Node upgrade readiness is assumed healthy unless there is pressure or unsupported runtime evidence."},
        "Control Plane": {"Status": "pass", "Severity": "Low", "Explanation": "Control plane upgrade exposure is presumed low unless compatibility risk is known."},
    }

    issues = _build_issues(data)

    for issue in issues:
        category = issue["category"]
        if category == "General":
            continue
        domain = _domain_key(category)
        status = normalize_status(issue["status"])
        if status == "verified":
            area_status = "warning" if category not in {"APIs", "CRDs", "controllers"} else "high-risk"
        elif status == "probable":
            area_status = "warning"
        else:
            area_status = "warning"

        status_label = area_status.capitalize() if area_status not in {"high-risk"} else "HIGH-RISK"
        if area_status == "high-risk":
            status_label = "HIGH-RISK"
        elif area_status == "warning":
            status_label = "WARNING"
        _update_area_status(areas, domain, area_status, f"{issue['title']}: {issue['details']}")

    missing_sections = sum(1 for section in ["cluster_info", "workloads", "crds", "controllers", "admission_webhooks", "networking", "storage", "security", "runtime", "resource_pressure"] if section not in data)
    readiness, confidence = _compute_score(areas, issues, missing_sections)

    # Explicit risk declaration that matches the mandatory rule.
    resolution_issue = next((issue for issue in issues if issue["severity"] in {"high", "critical"}), issues[0])
    mandatory_risk = {
        "what_will_break": resolution_issue["title"],
        "when_it_will_break": "Control Plane Upgrade / Node Upgrade / Immediately After Upgrade / First Reconciliation / First Deployment",
        "impact": "Outage / Partial Outage / Reconciliation Failure / Deployment Failure / Data Risk",
        "severity": resolution_issue["severity"].capitalize(),
        "remediation": "Validate compatibility, upgrade affected controllers and CRDs before the Kubernetes control plane cutover, and test a staged drain with rollback criteria.",
    }

    assessment = {
        "source_version": source_version,
        "target_version": target_version,
        "decision": _upgrade_decision(readiness),
        "readiness_score": readiness,
        "confidence_score": confidence,
        "areas": areas,
        "issues": issues,
        "mandatory_risk": mandatory_risk,
        "verified_issues": [issue for issue in issues if issue["status"] == "verified"],
        "probable_issues": [issue for issue in issues if issue["status"] == "probable"],
        "possible_issues": [issue for issue in issues if issue["status"] == "possible"],
        "unknown_risks": [issue for issue in issues if issue["status"] == "possible" and issue["category"] == "Unknown"],
    }
    return assessment


def generate_assessment_report(assessment: Dict[str, Any]) -> str:
    areas = assessment["areas"]
    issue_blocks = {"verified": assessment["verified_issues"], "probable": assessment["probable_issues"], "possible": assessment["possible_issues"], "unknown": assessment["unknown_risks"]}

    matrix = [
        "| Area          | Status | Severity | Explanation |",
        "| ------------- | ------ | -------- | ----------- |",
    ]
    for domain in DOMAIN_NAMES:
        area = areas.get(domain, {"Status": "warning", "Severity": "Medium", "Explanation": "No decision path was available."})
        explanation = str(area.get("Explanation", "No evidence found."))
        matrix.append(f"| {domain:<13} | {str(area.get('Status', 'WARNING')):<6} | {str(area.get('Severity', 'Medium')):<8} | {explanation[:90]} |")

    def _format_issues(bucket: Iterable[Dict[str, Any]]) -> str:
        items = list(bucket)
        if not items:
            return "- None identified from supplied evidence."
        return "\n".join(f"- {item['title']}: {item['details']}" for item in items)

    report = [
        "# Kubernetes Upgrade Feasibility, Compatibility, and Risk Assessment",
        "",
        "## Executive Summary",
        "",
        "UPGRADE DECISION:",
        f"{assessment['decision']}",
        "",
        "SOURCE VERSION:",
        str(assessment["source_version"]),
        "",
        "TARGET VERSION:",
        str(assessment["target_version"]),
        "",
        "READINESS SCORE:",
        f"{assessment['readiness_score']}/100",
        "",
        "CONFIDENCE:",
        f"{assessment['confidence_score']}%",
        "",
        "CRITICAL ISSUES:",
        _format_issues(issue for issue in assessment["verified_issues"] if normalize_severity(issue["severity"]) in {"high", "critical"}) or "- None identified from supplied evidence.",
        "",
        "HIGH RISKS:",
        _format_issues(issue for issue in assessment["probable_issues"] if normalize_severity(issue["severity"]) in {"high", "critical"}) or "- None identified from supplied evidence.",
        "",
        "WARNINGS:",
        _format_issues(issue for issue in assessment["probable_issues"] if normalize_severity(issue["severity"]) == "medium") or "- None identified from supplied evidence.",
        "",
        "REQUIRED ACTIONS BEFORE UPGRADE:",
        "1. Upgrade or validate all unsupported controllers and operators against the target Kubernetes version.",
        "2. Migrate deprecated CRDs and APIs before the control-plane cutover.",
        "3. Validate admission webhook and storage compatibility in a non-production environment.",
        "",
        "RECOMMENDED UPGRADE ORDER:",
        "1. Remediate or upgrade unsupported operators and CRDs.",
        "2. Validate webhooks and storage layers in a staging cluster.",
        "3. Perform a controlled node and control-plane rollout with rollback criteria.",
        "",
        "POST-UPGRADE VALIDATIONS:",
        "1. Verify control plane health and API server readiness.",
        "2. Validate workloads, webhooks, and controller reconciliation.",
        "3. Confirm storage class, CSI, and networking health after the rollout.",
        "",
        "FINAL RECOMMENDATION:",
        f"The cluster should not proceed to {assessment['target_version']} without fixing the compatibility issues identified above. This assessment is intentionally conservative and should be validated against the live production cluster and vendor support matrices before the final upgrade window.",
        "",
        "## Mandatory Risk Declaration",
        "",
        "WHAT WILL BREAK:",
        assessment["mandatory_risk"]["what_will_break"],
        "",
        "WHEN IT WILL BREAK:",
        assessment["mandatory_risk"]["when_it_will_break"],
        "",
        "IMPACT:",
        assessment["mandatory_risk"]["impact"],
        "",
        "SEVERITY:",
        assessment["mandatory_risk"]["severity"],
        "",
        "REMEDIATION:",
        assessment["mandatory_risk"]["remediation"],
        "",
        "## Verified Issues",
        "",
        _format_issues(assessment["verified_issues"]),
        "",
        "## Probable Issues",
        "",
        _format_issues(assessment["probable_issues"]),
        "",
        "## Possible Issues",
        "",
        _format_issues(assessment["possible_issues"]),
        "",
        "## Unknown Risks",
        "",
        _format_issues(assessment["unknown_risks"]),
        "",
        "## Risk Matrix",
        "",
        *matrix,
        "",
        "## Readiness Score",
        "",
        f"Readiness Score: {assessment['readiness_score']}/100",
        "",
        "## Confidence Score",
        "",
        f"Confidence Score: {assessment['confidence_score']}%",
        "",
        "## Upgrade Simulation",
        "",
        "### Control Plane",
        "Status: " + areas.get("Control Plane", {}).get("Status", "WARNING"),
        "Reason: The target version requires validated control-plane compatibility and operator support before the cutover.",
        "",
        "### Nodes",
        "Status: " + areas.get("Nodes", {}).get("Status", "WARNING"),
        "Reason: Node drain and kubelet upgrade risk remains elevated when resources are constrained or runtime support is uncertain.",
        "",
        "### APIs",
        "Status: " + areas.get("APIs", {}).get("Status", "WARNING"),
        "Reason: Deprecated or removed APIs can prevent workloads from starting or controllers from reconciling after the upgrade.",
        "",
        "### CRDs",
        "Status: " + areas.get("CRDs", {}).get("Status", "WARNING"),
        "Reason: Storage-version and served-version mismatches can block CRD reads or writes during upgrade events.",
        "",
        "### Controllers",
        "Status: " + areas.get("Controllers", {}).get("Status", "WARNING"),
        "Reason: Unvalidated operators can fail to reconcile after the Kubernetes control-plane upgrade.",
        "",
        "### Networking",
        "Status: " + areas.get("Networking", {}).get("Status", "WARNING"),
        "Reason: Ingress or CNI changes may interrupt service reachability and DNS resolution following the rollout.",
        "",
        "### Storage",
        "Status: " + areas.get("Storage", {}).get("Status", "WARNING"),
        "Reason: CSI and snapshot compatibility can make persistent volumes temporarily inaccessible after the upgrade.",
        "",
        "### Security",
        "Status: " + areas.get("Security", {}).get("Status", "WARNING"),
        "Reason: Pod Security Admission or policy changes may prevent workloads from starting after the upgrade.",
        "",
    ]

    return "\n".join(report)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assess Kubernetes upgrade readiness from a supplied cluster inventory.")
    parser.add_argument("--source-version", required=True, help="Current Kubernetes version (example: 1.25)")
    parser.add_argument("--target-version", required=True, help="Target Kubernetes version (example: 1.29)")
    parser.add_argument("--input", help="Path to JSON cluster inventory file", default=None)
    parser.add_argument("--output", help="Optional markdown output path", default=None)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    data = {}
    if args.input:
        with Path(args.input).open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = {"cluster_info": {"kubernetes_version": args.source_version, "managed_cluster": True}, "workloads": [], "crds": [], "controllers": [], "admission_webhooks": [], "networking": {"status": "warning", "notes": "No explicit networking evidence provided."}, "storage": {"status": "warning", "notes": "No explicit storage evidence provided."}, "security": {"status": "warning", "notes": "No explicit security evidence provided."}, "runtime": {"status": "warning", "notes": "No explicit runtime evidence provided."}, "resource_pressure": {"status": "warning", "notes": "No resource-pressure evidence provided."}}

    assessment = assess_cluster(data, args.source_version, args.target_version)
    report = generate_assessment_report(assessment)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
